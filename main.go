package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// Configuration structure
type Config struct {
	DiscoveryURL  string `json:"discovery_url" env:"OIDC_DISCOVERY_URL"`
	ClientID      string `json:"client_id" env:"OIDC_CLIENT_ID"`
	RedirectURL   string `json:"redirect_url" env:"OIDC_REDIRECT_URL"`
	Scopes        string `json:"scopes" env:"OIDC_SCOPES"`
	MinioEndpoint string `json:"minio_endpoint" env:"MINIO_ENDPOINT"`
}

// AWS Credentials structure
type Credentials struct {
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

// STS Response structure
type AssumeRoleResponse struct {
	XMLName xml.Name `xml:"AssumeRoleWithWebIdentityResponse"`
	Result  struct {
		Credentials struct {
			AccessKeyId     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"Credentials"`
	} `xml:"AssumeRoleWithWebIdentityResult"`
}

// OIDC Discovery Response
type OIDCDiscoveryResponse struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

var (
	oauthConfig  *oauth2.Config
	server       *http.Server
	codeVerifier string
	config       *Config
)

func main() {
	// Load configuration
	var err error
	config, err = loadConfig()
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	// Discover OIDC endpoints
	oidcEndpoints, err := discoverOIDCEndpoints(config.DiscoveryURL)
	if err != nil {
		log.Fatalf("OIDC discovery failed: %v", err)
	}

	// Parse scopes
	scopes := strings.Split(config.Scopes, " ")
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	// Configure OAuth2 without client secret
	oauthConfig = &oauth2.Config{
		ClientID: config.ClientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:  oidcEndpoints.AuthorizationEndpoint,
			TokenURL: oidcEndpoints.TokenEndpoint,
		},
		RedirectURL: config.RedirectURL,
		Scopes:      scopes,
	}

	// Parse redirect URL to determine server port
	redirectURL, err := url.Parse(config.RedirectURL)
	if err != nil {
		log.Fatalf("Invalid redirect URL: %v", err)
	}

	// Start local server for OAuth callback
	http.HandleFunc(redirectURL.Path, callbackHandler)
	serverAddr := "localhost"
	if redirectURL.Host != "" {
		serverAddr = redirectURL.Host
	}
	server = &http.Server{Addr: serverAddr}
	log.Printf("Starting callback server on %s", serverAddr)
	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Generate PKCE code verifier and challenge
	codeVerifier = generateCodeVerifier()
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Build authorization URL with PKCE parameters
	authURL := oauthConfig.AuthCodeURL("state",
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	// Open browser for authentication
	openBrowser(authURL)

	// Wait for shutdown signal
	select {
	case <-time.After(5 * time.Minute):
		log.Fatal("Timed out waiting for authentication")
	}
}

// Generate PKCE code verifier (RFC 7636)
func generateCodeVerifier() string {
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		log.Fatalf("Failed to generate code verifier: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes)
}

// Generate PKCE code challenge (S256 method)
func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// Load configuration from file and environment
func loadConfig() (*Config, error) {
	cfg := &Config{}

	// Default values
	cfg.RedirectURL = "http://localhost:8000/oauth2/callback"
	cfg.Scopes = "openid email profile"

	// Try to load from config file
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	configPath := filepath.Join(homeDir, ".s3-token-config")
	if file, err := os.Open(configPath); err == nil {
		defer file.Close()
		if err := json.NewDecoder(file).Decode(cfg); err != nil {
			log.Printf("Warning: Error reading config file: %v", err)
		}
	}

	// Override with environment variables
	if v := os.Getenv("OIDC_DISCOVERY_URL"); v != "" {
		cfg.DiscoveryURL = v
	}
	if v := os.Getenv("OIDC_CLIENT_ID"); v != "" {
		cfg.ClientID = v
	}
	if v := os.Getenv("OIDC_REDIRECT_URL"); v != "" {
		cfg.RedirectURL = v
	}
	if v := os.Getenv("OIDC_SCOPES"); v != "" {
		cfg.Scopes = v
	}
	if v := os.Getenv("MINIO_ENDPOINT"); v != "" {
		cfg.MinioEndpoint = v
	}

	// Validate required values
	if cfg.DiscoveryURL == "" {
		return nil, fmt.Errorf("OIDC discovery URL is required")
	}
	if cfg.MinioEndpoint == "" {
		return nil, fmt.Errorf("minio endpoint is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("client ID is required")
	}

	return cfg, nil
}

// Discover OIDC endpoints
func discoverOIDCEndpoints(discoveryURL string) (*OIDCDiscoveryResponse, error) {
	resp, err := http.Get(discoveryURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("discovery request failed: %s\n%s", resp.Status, body)
	}

	var discovery OIDCDiscoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, err
	}

	if discovery.AuthorizationEndpoint == "" || discovery.TokenEndpoint == "" {
		return nil, fmt.Errorf("invalid discovery response: missing required endpoints")
	}

	return &discovery, nil
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Authorization code missing", http.StatusBadRequest)
		return
	}

	// Exchange code for access token using PKCE
	token, err := oauthConfig.Exchange(
		context.Background(),
		code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		log.Printf("Token exchange error: %v", err)
		return
	}

	// Get AWS credentials using access token
	creds, err := getAWSCredentials(token.AccessToken)
	if err != nil {
		http.Error(w, "Failed to get AWS credentials", http.StatusInternalServerError)
		log.Printf("AWS credential error: %v", err)
		return
	}

	// Save credentials to file
	if err := saveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		log.Printf("Save error: %v", err)
		return
	}

	fmt.Fprintln(w, "Authentication successful! Credentials saved to ~/.s3-token")

	// Shutdown server and exit program
	go func() {
		// Give time for response to be delivered
		time.Sleep(100 * time.Millisecond)

		// Shutdown HTTP server
		if err := server.Shutdown(context.Background()); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}

		// Exit program successfully
		os.Exit(0)
	}()
}

func getAWSCredentials(accessToken string) (*Credentials, error) {
	// Prepare form data
	form := url.Values{}
	form.Add("Action", "AssumeRoleWithWebIdentity")
	form.Add("Version", "2011-06-15")
	form.Add("WebIdentityToken", accessToken)

	// Send POST request to configurable MinIO endpoint
	resp, err := http.PostForm(config.MinioEndpoint, form)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("STS request failed: %s\n%s", resp.Status, body)
	}

	// Parse XML response
	var stsResponse AssumeRoleResponse
	if err := xml.NewDecoder(resp.Body).Decode(&stsResponse); err != nil {
		return nil, err
	}

	return &Credentials{
		AccessKeyId:     stsResponse.Result.Credentials.AccessKeyId,
		SecretAccessKey: stsResponse.Result.Credentials.SecretAccessKey,
		SessionToken:    stsResponse.Result.Credentials.SessionToken,
		Expiration:      stsResponse.Result.Credentials.Expiration,
	}, nil
}

func saveCredentials(creds *Credentials) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	filePath := filepath.Join(homeDir, ".s3-token")
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, data, 0600)
}

func openBrowser(url string) {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default: // linux, freebsd, etc.
		cmd = "xdg-open"
	}
	args = append(args, url)

	if err := exec.Command(cmd, args...).Start(); err != nil {
		log.Printf("Failed to open browser: %v", err)
	}
}

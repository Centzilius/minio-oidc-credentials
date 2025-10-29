# minio-oidc-credentials
Exchange a JWT for an AWS STS token on your MinIO server. Tested with Keycloak and originally created to store Terraform State on MinIO without creating unnecessary long-lived credentials.

## Configuration
This tool can be either configured using a json config file (`$HOME/.s3-token-config`) or using environment variables.

| JSON Config Key | Environment Variable Name | Required | Description / Example                                                                               | Default                                 |
|-----------------|---------------------------|----------|-----------------------------------------------------------------------------------------------------|-----------------------------------------|
| minio_endpoint  | MINIO_ENDPOINT            | Yes      | https://s3.example.com                                                                              | N/A                                     |
| discovery_url   | OIDC_DISCOVERY_URL        | Yes      | sso.example.com/realms/master/.well-known/openid-configuration                                      | N/A                                     |
| client_id       | OIDC_CLIENT_ID            | Yes      | Client ID for authentication against the OIDC IDP                                                   | N/A                                     |
| redirect_url    | OIDC_REDIRECT_URL         | No       | URL the IDP should redirect the user to after authentication. This also configures the listen port. | `http://localhost:8000/oauth2/callback` |
| scopes          | OIDC_SCOPES               | No       | Scopes to request from the IDP (space separated)                                                    | `openid email profile`                  |

## Usage
1. Create a PKCE enabled client application in your IDP that has the required configuration for MinIO to accept its JWT.
2. Configure this tool according to the table above
3. Run it `minio-oidc-credentials`
4. Find your STS token in `$HOME/.s3-token`

## Example usage with OpenToFu
```bash
#!/bin/bash
S3_CREDENTIAL_FILE=$HOME/.s3-token
export OIDC_DISCOVERY_URL=https://sso.example.com/realms/master/.well-known/openid-configuration
export OIDC_CLIENT_ID=terraform-states
export MINIO_ENDPOINT=https://s3.example.com
minio-oidc-credentials || exit 1

export AWS_ACCESS_KEY_ID=$(cat $S3_CREDENTIAL_FILE | jq -r .AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(cat $S3_CREDENTIAL_FILE | jq -r .SecretAccessKey)
export AWS_SESSION_TOKEN=$(cat $S3_CREDENTIAL_FILE | jq -r .SessionToken)

tofu "$@"
```

```terraform
terraform {
  backend "s3" {
    bucket = "tfstate"
    endpoints = {
      s3 = "https://s3.example.com"
      sts = "https://s3.example.com"
      iam = "https://s3.example.com"
    }
    key = "your-advertisement-here.tfstate"
    region = "some-region-name"
    skip_region_validation = true
    skip_credentials_validation = true
    use_path_style = true
  }
}
```

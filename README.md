# Token Gateway Proxy

A lightweight OAuth2-aware reverse proxy for forwarding HTTP GET requests to upstream APIs that require bearer token authentication via the `client_credentials` flow. Now with multi-cloud support for AWS and Azure, enabling seamless integration with cloud provider APIs alongside Forward Networks and other systems requiring secure, token-based access.

---

## Features

- 🔐 OAuth2 `client_credentials` token flow
- ☁️ Multi-cloud support for AWS and Azure
- 🔄 SDK-backed request translation (e.g. DescribeInstances)
- 📦 Converts AWS XML responses to JSON
- 🧠 In-memory token caching per (client_id + token URL)
- 🔄 Transparent forwarding of authorized GET requests
- 🗜️ Handles gzip-compressed upstream responses
- 🔒 TLS support (with fallback to self-signed certificates)
- 🔧 Configurable via HTTP headers and environment variables

---

## How It Works

### For OAuth2 (Generic)

The proxy accepts requests from clients using HTTP Basic Auth credentials (`client_id:client_secret`). It:
1. Fetches an access token from the specified `X-Token-URL`.
2. Caches the token in memory until expiration.
3. Forwards the request to the upstream URL specified by combining `X-Upstream-Host` with the original request path.
4. Adds `Authorization: Bearer {access_token}` to the upstream request.
5. Returns the upstream response to the client, decoding gzip if needed.

### For AWS

The proxy accepts Basic Auth using AWS credentials (`access_key:secret_key`) or uses an EC2 instance profile. It:
1. Parses the request path as `/SERVICE/ACTION`, e.g. `/ec2/DescribeInstances`.
2. Constructs the appropriate API call using the AWS SDK.
3. Automatically converts XML responses to JSON.
4. Supports multi-region requests.

Required Header:
- `X-AWS-Region`: Comma-separated list of AWS regions

Optional Header:
- `X-Use-Instance-Profile: 1` to use the instance metadata service

### For Azure

The proxy accepts Basic Auth using Azure credentials (`client_id:client_secret`) and requires a tenant header.
1. Uses the `X-Azure-Tenant` header to authenticate.
2. Calls Azure REST APIs using the provided client/secret.
3. Forwards authenticated results to the client.

Required Header:
- `X-Azure-Tenant`: Azure tenant ID

---

## Example Client Request

```http
GET /upstream/api/resource HTTP/1.1
Host: token-gw.local
Authorization: Basic base64(client_id:client_secret)
X-Token-URL: https://auth.example.com/oauth2/token
X-Upstream-Host: https://api.example.com
```

### AWS Example

```http
GET /ec2/DescribeInstances HTTP/1.1
Host: token-gw.local
Authorization: Basic base64(aws_access_key:aws_secret_key)
X-AWS-Region: us-east-1
```

### Azure Example

```http
GET /azure/subscriptions HTTP/1.1
Host: token-gw.local
Authorization: Basic base64(client_id:client_secret)
X-Azure-Tenant: your-tenant-id
```

---

## Required Headers

| Header            | Description                                                                 |
|-------------------|-----------------------------------------------------------------------------|
| `X-Token-URL`     | OAuth2 token endpoint (e.g. `https://auth.example.com/oauth2/token`)        |
| `X-Upstream-Host` | Full upstream base URL, including `https://` (e.g. `https://api.example.com`) |
| `X-AWS-Region`    | Required for AWS SDK requests (e.g. `us-west-2`)                            |
| `X-Azure-Tenant`  | Required for Azure SDK authentication                                       |

---

## Optional Headers

| Header              | Description                                                 | Default        |
|---------------------|-------------------------------------------------------------|----------------|
| `X-Token-Field`     | JSON field in token response that contains the token        | `access_token` |
| `X-Header-Prefix`   | Authorization header prefix                                 | `Bearer `      |

---

## Environment Variables

| Variable             | Description                                                  | Default       |
|----------------------|--------------------------------------------------------------|---------------|
| `PORT`               | Port to listen on (required)                                 | N/A           |
| `DEBUG`              | Enable debug logging (set to `1` to enable)                  | Disabled      |
| `ALLOW_INSECURE_TLS` | Skip TLS verification for token and upstream calls           | Disabled      |
| `TLS_CERT`           | Path to TLS certificate (optional)                           | Auto-generate |
| `TLS_KEY`            | Path to TLS private key (optional)                           | Auto-generate |

---

## Building & Running

```bash
go build -o token-gateway main.go

PORT=8443 ./token-gateway
```

---

## Security Notes

- Tokens are cached in-memory, keyed by client credentials and token URL.
- TLS is enforced by default. Self-signed certs are used if none are provided.
- To connect to upstreams with self-signed certs, set `ALLOW_INSECURE_TLS=1`.

---

## Disclaimer

This project is provided as-is, without warranty of any kind. It is not an officially supported product and is intended for use by Forward Networks customers and technical teams who need lightweight OAuth2-to-Basic Auth translation for custom data integrations.

Use at your own risk. Contributions and feedback are welcome.

---

## License

MIT License
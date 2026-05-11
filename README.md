# Connector Gateway Proxy

A lightweight connector proxy for forwarding requests to upstream APIs. It supports OAuth2 `client_credentials` token exchange, basic-auth pass-through reverse proxying, and multi-cloud support for AWS and Azure.

---

## Features

- 🔐 OAuth2 `client_credentials` token flow
- 🔁 Basic-auth pass-through reverse proxy mode
- ☁️ Multi-cloud support for AWS and Azure
- 🔄 SDK-backed request translation (e.g. DescribeInstances)
- 🧠 In-memory token caching per (client_id + token URL)
- 🔄 Transparent forwarding of upstream requests and bodies
- 🗜️ Handles gzip-compressed upstream responses
- 🔒 TLS support (with fallback to self-signed certificates)
- 🔧 Configurable via HTTP headers and environment variables

---

## How It Works

### For OAuth2 (Generic)

The proxy accepts requests from clients using HTTP Basic Auth credentials (`client_id:client_secret`). It:
1. Fetches an access token from the specified `X-Token-URL`.
2. Caches the token in memory until expiration.
3. Forwards the request to the upstream URL specified by `X-Upstream-URL` or by combining `X-Upstream-Base-URL` with the original request path.
4. Adds `Authorization: Bearer {access_token}` to the upstream request.
5. Returns the upstream response to the client, decoding gzip if needed.

### For Generic Pass-Through

When `X-Token-URL` is omitted, the proxy runs in pass-through mode. It:
1. Uses the incoming request method and body as-is.
2. Forwards the incoming `Authorization` header unchanged.
3. Sends the request to `X-Upstream-URL` or combines `X-Upstream-Base-URL` with the incoming path and query string.
4. Returns the upstream response to the client, decoding gzip if needed.

Optional upstream overrides can be provided with headers:

- `X-Upstream-Method`: Override the method sent upstream.
- `X-Upstream-Body`: Override the upstream request body.
- `X-Upstream-Content-Type`: Override the upstream `Content-Type`.
- `X-Upstream-Accept`: Override the upstream `Accept`.
- `X-Upstream-Authorization`: Override the upstream `Authorization`.

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

### Generic Pass-Through Example

```http
POST /api/v1/fortimanager/jsonrpc HTTP/1.1
Host: connector-gw.local
Authorization: Basic base64(fortimanager_user:fortimanager_password)
X-Upstream-Base-URL: https://fortimanager.example.com
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
| `X-Upstream-URL`  | Full upstream URL for a single request                                      |
| `X-Upstream-Base-URL` | Base upstream URL that will be combined with the incoming path and query |
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

## Mode Selection

- If `X-Token-URL` is present, the request runs in OAuth2 token-exchange mode.
- If `X-Token-URL` is absent, the request runs in generic pass-through mode.
- AWS and Azure request handling remains available through their existing request-path conventions.

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

This project is provided as-is, without warranty of any kind. It is not an officially supported product and is intended for use by Forward Networks customers and technical teams who need a lightweight connector proxy for custom API integrations.

Use at your own risk. Contributions and feedback are welcome.

---

## License

MIT License

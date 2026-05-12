# Connector Gateway Proxy

A lightweight connector proxy for forwarding requests to upstream APIs. It supports OAuth2 `client_credentials` token exchange, session-cookie authentication, basic-auth pass-through reverse proxying, and multi-cloud support for AWS and Azure.

---

## Features

- 🔐 OAuth2 `client_credentials` token flow
- 🍪 Session-cookie login flow for APIs that cannot accept Basic auth per request
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

### For Generic Session-Cookie APIs

When `X-Auth-Mode: session`, `PROXY_AUTH_MODE=session`, `X-Session-Login-URL`, or `SESSION_LOGIN_URL` is set, the proxy uses the incoming Basic Auth credentials only to authenticate to the upstream login endpoint. It:
1. Logs in to the upstream API with `username` and `password` form fields by default.
2. Caches the returned session cookies in memory.
3. Forwards the original request path and query string to `X-Upstream-Base-URL` or `UPSTREAM_BASE_URL`.
4. Replaces the client Basic Auth header with the upstream session cookies.
5. Adds the configured CSRF header and `Referer` when a CSRF token is returned.
6. Refreshes the session and retries once on `401` or `403`.

This mode is generic. It is useful for API platforms where the client can only send Basic Auth to the proxy, but the upstream requires login-session cookies, CSRF headers, or another form-post login flow.

For VMware Avi Load Balancer / NSX Advanced Load Balancer environments where Basic Authentication is disabled, the Forward AVI collector can send Basic Auth to this gateway while the gateway performs session authentication against the real controller.

For Avi, configure the gateway with:

```bash
PORT=8443 \
PROXY_AUTH_MODE=session \
UPSTREAM_BASE_URL=https://avi-controller.example.com \
SESSION_LOGIN_URL=https://avi-controller.example.com/login \
ALLOW_INSECURE_TLS=1 \
./token-gateway
```

Then configure Forward's Avi API source to use the gateway host as the Avi controller. Forward's requests to `/api/...`, query strings such as `page=`, and headers such as `X-Avi-Tenant` are forwarded to the real controller.

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

### Generic Session-Cookie Example

```http
GET /api/virtualservice?page=1 HTTP/1.1
Host: connector-gw.local
Authorization: Basic base64(avi_user:avi_password)
X-Auth-Mode: session
X-Upstream-Base-URL: https://avi-controller.example.com
X-Session-Login-URL: https://avi-controller.example.com/login
X-Avi-Tenant: admin
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
| `X-Auth-Mode`     | Set to `session` for session-cookie mode                                    |
| `X-Session-Login-URL` | Login endpoint for session-cookie mode                                 |
| `X-AWS-Region`    | Required for AWS SDK requests (e.g. `us-west-2`)                            |
| `X-Azure-Tenant`  | Required for Azure SDK authentication                                       |

---

## Optional Headers

| Header              | Description                                                 | Default        |
|---------------------|-------------------------------------------------------------|----------------|
| `X-Token-Field`     | JSON field in token response that contains the token        | `access_token` |
| `X-Header-Prefix`   | Authorization header prefix                                 | `Bearer `      |
| `X-Session-Login-Content-Type` | Content type for session login request         | `application/x-www-form-urlencoded` |
| `X-Session-Login-Body` | Template for session login body; supports `{{username}}` and `{{password}}` | `username=...&password=...` |
| `X-Session-Username-Field` | Username form field for default session login body   | `username` |
| `X-Session-Password-Field` | Password form field for default session login body   | `password` |
| `X-Session-Cache-Seconds` | Session cache lifetime in seconds                    | `1800` |
| `X-Session-CSRF-Cookie-Names` | Comma-separated cookie names to inspect for a CSRF token | `csrftoken,csrf_token` |
| `X-Session-CSRF-Header` | Header used to forward the CSRF token upstream        | `X-CSRFToken` |

---

## Environment Variables

| Variable             | Description                                                  | Default       |
|----------------------|--------------------------------------------------------------|---------------|
| `PORT`               | Port to listen on (required)                                 | N/A           |
| `DEBUG`              | Enable debug logging (set to `1` to enable)                  | Disabled      |
| `ALLOW_INSECURE_TLS` | Skip TLS verification for token and upstream calls           | Disabled      |
| `TLS_CERT`           | Path to TLS certificate (optional)                           | Auto-generate |
| `TLS_KEY`            | Path to TLS private key (optional)                           | Auto-generate |
| `PROXY_AUTH_MODE`    | Set to `session` to enable session-cookie mode by default    | N/A           |
| `UPSTREAM_URL`       | Full upstream URL fallback                                   | N/A           |
| `UPSTREAM_BASE_URL`  | Base upstream URL fallback                                   | N/A           |
| `SESSION_LOGIN_URL`  | Session login URL fallback                                   | N/A           |
| `SESSION_LOGIN_CONTENT_TYPE` | Session login content type fallback                 | `application/x-www-form-urlencoded` |
| `SESSION_LOGIN_BODY` | Session login body template fallback                         | N/A           |
| `SESSION_USERNAME_FIELD` | Username form field fallback                             | `username`    |
| `SESSION_PASSWORD_FIELD` | Password form field fallback                             | `password`    |
| `SESSION_CSRF_COOKIE_NAMES` | Comma-separated cookie names to inspect for a CSRF token | `csrftoken,csrf_token` |
| `SESSION_CSRF_HEADER` | Header used to forward the CSRF token upstream              | `X-CSRFToken` |

---

## Mode Selection

- If `X-Token-URL` is present, the request runs in OAuth2 token-exchange mode.
- If session mode is enabled with `X-Auth-Mode: session`, `PROXY_AUTH_MODE=session`, `X-Session-Login-URL`, or `SESSION_LOGIN_URL`, the request runs in session-cookie mode.
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

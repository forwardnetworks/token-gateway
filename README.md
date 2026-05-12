# Connector Gateway Proxy

A lightweight proxy for forwarding client requests to upstream APIs that need a different authentication or request format than the client can natively provide.

The common deployment pattern is:

1. The client sends a normal request to the gateway, usually with Basic Auth.
2. The gateway applies authentication or request translation.
3. The gateway forwards the request path, query string, method, body, and allowed headers to the configured upstream API.
4. The gateway returns the upstream response.

For clients that cannot send custom control headers, configure the gateway with environment variables.

---

## Features

- OAuth2 `client_credentials` token exchange
- Session-cookie login for upstream APIs that cannot accept Basic Auth per request
- Basic-auth pass-through reverse proxy mode
- AWS and Azure request translation paths
- In-memory token and session caching
- Transparent forwarding of upstream request paths, query strings, methods, bodies, and responses
- Gzip response handling
- TLS support, with optional self-signed certificate fallback
- Configuration through environment variables, with optional header overrides for flexible clients

---

## Modes

### OAuth2 Token Exchange

The gateway accepts Basic Auth credentials from the client, uses them as `client_id:client_secret`, retrieves an OAuth2 token, and forwards the upstream request with `Authorization: Bearer <token>`.

Enable this mode with `TOKEN_URL` or `X-Token-URL`.

### Session-Cookie Login

The gateway accepts Basic Auth credentials from the client, posts them to an upstream login endpoint, caches the returned cookies, and forwards upstream requests with the session cookies instead of the client Basic Auth header.

Enable this mode with `PROXY_AUTH_MODE=session`, `SESSION_LOGIN_URL`, `X-Auth-Mode: session`, or `X-Session-Login-URL`.

The login request is generic:

- Default content type: `application/x-www-form-urlencoded`
- Default username field: `username`
- Default password field: `password`
- Custom login body templates can use `{{username}}` and `{{password}}`
- CSRF cookie names and the outbound CSRF header are configurable

### Basic Pass-Through

When token and session modes are not enabled, the gateway forwards the request to the configured upstream and keeps the incoming `Authorization` header unless overridden.

This mode has been tested with a FortiManager JSON-RPC data-connector workflow.

---

## Forward-Compatible Configuration

Use environment variables when the client cannot send gateway control headers.

### Basic Pass-Through

```bash
PORT=8443 \
UPSTREAM_BASE_URL=https://upstream.example.com \
./token-gateway
```

### OAuth2 Token Exchange

```bash
PORT=8443 \
TOKEN_URL=https://auth.example.com/oauth2/token \
UPSTREAM_BASE_URL=https://api.example.com \
./token-gateway
```

### Session-Cookie Login

```bash
PORT=8443 \
PROXY_AUTH_MODE=session \
UPSTREAM_BASE_URL=https://api.example.com \
SESSION_LOGIN_URL=https://api.example.com/login \
./token-gateway
```

In all three examples, the client only needs to call the gateway URL and provide the credentials it normally supports. The gateway supplies the upstream destination and authentication behavior.

---

## Environment Variables

| Variable | Description | Default |
| --- | --- | --- |
| `PORT` | Port to listen on | Required |
| `DEBUG` | Set to `1` for debug logging | Disabled |
| `ALLOW_INSECURE_TLS` | Set to `1` to skip upstream TLS verification | Disabled |
| `TLS_CERT` | TLS certificate path | Auto-generate |
| `TLS_KEY` | TLS private key path | Auto-generate |
| `UPSTREAM_URL` | Full upstream URL for every request | N/A |
| `UPSTREAM_BASE_URL` | Base upstream URL combined with the incoming path and query string | N/A |
| `UPSTREAM_METHOD` | Override upstream method | Incoming method |
| `UPSTREAM_BODY` | Override upstream request body | Incoming body |
| `UPSTREAM_CONTENT_TYPE` | Override upstream `Content-Type` | Incoming header |
| `UPSTREAM_ACCEPT` | Override upstream `Accept` | Incoming header |
| `UPSTREAM_AUTHORIZATION` | Override upstream `Authorization` | Incoming header or mode-specific auth |
| `TOKEN_URL` | OAuth2 token endpoint | N/A |
| `TOKEN_FIELD` | JSON field containing the token | `access_token` |
| `TOKEN_HEADER_PREFIX` | Upstream authorization prefix | `Bearer ` |
| `TOKEN_CACHE_SECONDS` | Fallback token cache TTL | `1800` |
| `PROXY_AUTH_MODE` | Set to `session` for session-cookie mode | N/A |
| `SESSION_LOGIN_URL` | Session login endpoint | Derived from `UPSTREAM_BASE_URL` + `/login` |
| `SESSION_LOGIN_CONTENT_TYPE` | Login request content type | `application/x-www-form-urlencoded` |
| `SESSION_LOGIN_BODY` | Login body template with `{{username}}` and `{{password}}` | Generated from username/password fields |
| `SESSION_USERNAME_FIELD` | Username form field for generated login body | `username` |
| `SESSION_PASSWORD_FIELD` | Password form field for generated login body | `password` |
| `SESSION_CACHE_SECONDS` | Session cache TTL | `1800` |
| `SESSION_CSRF_COOKIE_NAMES` | Comma-separated CSRF cookie names | `csrftoken,csrf_token` |
| `SESSION_CSRF_HEADER` | Header used to forward CSRF token | `X-CSRFToken` |

---

## Optional Header Overrides

For clients that can send custom headers, these headers override the matching environment variables:

| Header | Description |
| --- | --- |
| `X-Upstream-URL` | Full upstream URL |
| `X-Upstream-Base-URL` | Base upstream URL |
| `X-Upstream-Method` | Override upstream method |
| `X-Upstream-Body` | Override upstream body |
| `X-Upstream-Content-Type` | Override upstream `Content-Type` |
| `X-Upstream-Accept` | Override upstream `Accept` |
| `X-Upstream-Authorization` | Override upstream `Authorization` |
| `X-Token-URL` | OAuth2 token endpoint |
| `X-Token-Field` | JSON field containing the token |
| `X-Header-Prefix` | Upstream authorization prefix |
| `X-Token-Cache-Seconds` | Token cache TTL |
| `X-Auth-Mode` | Set to `session` for session-cookie mode |
| `X-Session-Login-URL` | Session login endpoint |
| `X-Session-Login-Content-Type` | Login request content type |
| `X-Session-Login-Body` | Login body template |
| `X-Session-Username-Field` | Username field for generated login body |
| `X-Session-Password-Field` | Password field for generated login body |
| `X-Session-Cache-Seconds` | Session cache TTL |
| `X-Session-CSRF-Cookie-Names` | Comma-separated CSRF cookie names |
| `X-Session-CSRF-Header` | Header used to forward CSRF token |

---

## AWS and Azure

AWS and Azure translation paths remain available for clients that can provide the required request shape and credentials.

AWS region is read from `X-AWS-Region`. Azure tenant is read from `X-Azure-Tenant`.

---

## Building and Running

```bash
go build -o token-gateway main.go
PORT=8443 ./token-gateway
```

---

## Security Notes

- Tokens and sessions are cached in memory only.
- TLS is enabled by default.
- Self-signed certificates are generated if `TLS_CERT` and `TLS_KEY` are not provided.
- Use `ALLOW_INSECURE_TLS=1` only for lab or controlled environments.

---

## Disclaimer

This project is provided as-is, without warranty of any kind. It is not an officially supported product and is intended for Forward Networks customers and technical teams who need a lightweight connector proxy for custom API integrations.

Use at your own risk. Contributions and feedback are welcome.

---

## License

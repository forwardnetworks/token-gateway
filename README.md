# Token Gateway Proxy

A lightweight OAuth2-aware reverse proxy for forwarding HTTP GET requests to upstream APIs that require bearer token authentication via the `client_credentials` flow. Ideal for integrating with Forward Networks and other systems requiring secure, token-based access.

---

## Features

- 🔐 OAuth2 `client_credentials` token flow
- 🧠 In-memory token caching per (client_id + token URL)
- 🔄 Transparent forwarding of authorized GET requests
- 🗜️ Handles gzip-compressed upstream responses
- 🔒 TLS support (with fallback to self-signed certificates)
- 🔧 Configurable via HTTP headers and environment variables

---

## How It Works

The proxy accepts requests from clients using HTTP Basic Auth credentials (`client_id:client_secret`). It:

1. Fetches an access token from the specified `X-Token-URL`.
2. Caches the token in memory until expiration.
3. Forwards the request to the upstream URL specified by combining `X-Upstream-Host` with the original request path.
4. Adds `Authorization: Bearer {access_token}` to the upstream request.
5. Returns the upstream response to the client, decoding gzip if needed.

---

## Example Client Request

```http
GET /upstream/api/resource HTTP/1.1
Host: token-gw.local
Authorization: Basic base64(client_id:client_secret)
X-Token-URL: https://auth.example.com/oauth2/token
X-Upstream-Host: https://api.example.com
```

---

## Required Headers

| Header            | Description                                                                 |
|-------------------|-----------------------------------------------------------------------------|
| `X-Token-URL`     | OAuth2 token endpoint (e.g. `https://auth.example.com/oauth2/token`)        |
| `X-Upstream-Host` | Full upstream base URL, including `https://` (e.g. `https://api.example.com`) |

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

## License

MIT License

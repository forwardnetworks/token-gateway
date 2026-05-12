package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	sts "github.com/aws/aws-sdk-go-v2/service/sts"
)

var (
	listenAddress = ":" + os.Getenv("PORT")
	tokenCache    = make(map[string]CachedToken)
	cacheLock     sync.Mutex
	debugMode     = os.Getenv("DEBUG") == "1"
	insecureTLS   = os.Getenv("ALLOW_INSECURE_TLS") == "1"

	httpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:       100,
			IdleConnTimeout:    90 * time.Second,
			DisableCompression: false,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecureTLS,
			},
		},
	}
)

type CachedToken struct {
	Token  string
	Expiry time.Time
}

type CachedSession struct {
	CookieHeader string
	CSRFToken    string
	CSRFHeader   string
	Referer      string
	Expiry       time.Time
}

var sessionCache = make(map[string]CachedSession)

func main() {
	if listenAddress == ":" {
		log.Fatal("[FATAL] PORT environment variable not set")
	}

	http.HandleFunc("/", proxyHandler)

	certFile := os.Getenv("TLS_CERT")
	keyFile := os.Getenv("TLS_KEY")

	if certFile != "" && keyFile != "" {
		log.Printf("[INFO] Starting HTTPS server with provided TLS cert on %s (debug mode: %v)", listenAddress, debugMode)
		log.Fatal(http.ListenAndServeTLS(listenAddress, certFile, keyFile, nil))
	} else {
		log.Printf("[INFO] No TLS_CERT and TLS_KEY provided, using self-signed cert on %s (debug mode: %v)", listenAddress, debugMode)

		srv := &http.Server{
			Addr:    listenAddress,
			Handler: nil,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}

		certFile := "self-signed.crt"
		keyFile := "self-signed.key"
		if err := generateSelfSignedCert(certFile, keyFile); err != nil {
			log.Fatalf("[FATAL] Failed to generate self-signed cert: %v", err)
		}
		log.Fatal(srv.ListenAndServeTLS(certFile, keyFile))
	}
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	if debugMode {
		log.Printf("[DEBUG] Incoming request: %s %s", r.Method, r.URL.String())
	}

	// AWS routing: parse /aws/service/ActionName or /service/ActionName
	awsPrefix := "/aws/"
	awsPath := r.URL.Path
	if strings.HasPrefix(awsPath, awsPrefix) {
		awsPath = strings.TrimPrefix(awsPath, awsPrefix)
	}
	awsPathParts := strings.Split(strings.TrimPrefix(awsPath, "/"), "/")
	if len(awsPathParts) == 2 && awsPathParts[0] != "" && awsPathParts[1] != "" {
		// If path is /aws/service/Action or /service/Action, handle AWS SDK dynamic dispatch
		handleAWSRequestWithSDK(w, r, awsPathParts[0], awsPathParts[1])
		return
	}
	// If path starts with /aws/, but not /aws/service/Action, return error
	if strings.HasPrefix(r.URL.Path, "/aws/") {
		http.Error(w, "Invalid AWS SDK path. Use /aws/{service}/{Action}", http.StatusBadRequest)
		return
	}

	tokenURL := r.Header.Get("X-Token-URL")
	if tokenURL != "" {
		proxyOAuth2Request(w, r, tokenURL)
		return
	}

	if strings.EqualFold(firstNonEmpty(r.Header.Get("X-Auth-Mode"), os.Getenv("PROXY_AUTH_MODE")), "session") ||
		firstNonEmpty(r.Header.Get("X-Session-Login-URL"), os.Getenv("SESSION_LOGIN_URL")) != "" {
		proxySessionRequest(w, r)
		return
	}

	proxyPassThroughRequest(w, r)
}

func proxyOAuth2Request(w http.ResponseWriter, r *http.Request, tokenURL string) {
	tokenField := r.Header.Get("X-Token-Field")
	if tokenField == "" {
		tokenField = "access_token"
	}
	headerPrefix := r.Header.Get("X-Header-Prefix")
	if headerPrefix == "" {
		headerPrefix = "Bearer "
	}
	cacheSecs := 1800 // fallback only
	username, password, ok := r.BasicAuth()
	if !ok {
		log.Printf("[WARN] Missing or invalid basic auth")
		w.Header().Set("WWW-Authenticate", `Basic realm="OAuth2 Proxy"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var accessKeyID, secretOrToken string
	if username != "" {
		accessKeyID = username
		secretOrToken = password
	} else {
		accessKeyID = "apikey"
		secretOrToken = password
	}
	log.Printf("[INFO] Authenticated client: %s", maskString(accessKeyID))
	token, err := getTokenForRoute(r.URL.Path, accessKeyID, secretOrToken, tokenURL, tokenField, cacheSecs)
	if err != nil {
		log.Printf("[ERROR] Token retrieval failed: %v", err)
		http.Error(w, "Failed to retrieve token", http.StatusBadGateway)
		return
	}

	targetURL, err := resolveUpstreamURL(r)
	if err != nil {
		log.Printf("[ERROR] %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req, err := newUpstreamRequest(r, targetURL)
	if err != nil {
		log.Printf("[ERROR] Failed to build upstream request: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	copyHeaders(req.Header, r.Header, true)
	req.Header.Set("Authorization", headerPrefix+token)
	applyUpstreamOverrides(req, r)
	doUpstreamRequest(w, req, targetURL)
}

func proxyPassThroughRequest(w http.ResponseWriter, r *http.Request) {
	targetURL, err := resolveUpstreamURL(r)
	if err != nil {
		log.Printf("[ERROR] %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req, err := newUpstreamRequest(r, targetURL)
	if err != nil {
		log.Printf("[ERROR] Failed to build upstream request: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	copyHeaders(req.Header, r.Header, false)
	applyUpstreamOverrides(req, r)
	doUpstreamRequest(w, req, targetURL)
}

func proxySessionRequest(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok {
		log.Printf("[WARN] Missing or invalid basic auth")
		w.Header().Set("WWW-Authenticate", `Basic realm="Session Proxy"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	targetURL, err := resolveUpstreamURL(r)
	if err != nil {
		log.Printf("[ERROR] %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := doSessionRequest(r, targetURL, username, password, false)
	if err == nil && resp != nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
		log.Printf("[WARN] Session rejected with %d; refreshing and retrying once", resp.StatusCode)
		resp.Body.Close()
		resp, err = doSessionRequest(r, targetURL, username, password, true)
	}
	if err != nil {
		log.Printf("[ERROR] Session upstream request failed: %v", err)
		http.Error(w, "Upstream API error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	writeUpstreamResponse(w, resp, targetURL)
}

func resolveUpstreamURL(r *http.Request) (string, error) {
	if targetURL := r.Header.Get("X-Upstream-URL"); targetURL != "" {
		return targetURL, nil
	}
	if targetURL := os.Getenv("UPSTREAM_URL"); targetURL != "" {
		return targetURL, nil
	}
	baseURL := firstNonEmpty(r.Header.Get("X-Upstream-Base-URL"), os.Getenv("UPSTREAM_BASE_URL"))
	if baseURL == "" {
		return "", fmt.Errorf("Missing X-Upstream-URL or X-Upstream-Base-URL header")
	}
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("Invalid X-Upstream-Base-URL: %w", err)
	}
	parsedBase.Path = strings.TrimRight(parsedBase.Path, "/") + r.URL.Path
	parsedBase.RawQuery = r.URL.RawQuery
	return parsedBase.String(), nil
}

func newUpstreamRequest(r *http.Request, targetURL string) (*http.Request, error) {
	method := r.Method
	if override := strings.TrimSpace(r.Header.Get("X-Upstream-Method")); override != "" {
		method = strings.ToUpper(override)
	}
	bodyBytes, err := readUpstreamBody(r)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Host = req.URL.Host
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodyBytes)), nil
	}
	return req, nil
}

func readUpstreamBody(r *http.Request) ([]byte, error) {
	if override := r.Header.Get("X-Upstream-Body"); override != "" {
		return []byte(override), nil
	}
	if r.Body == nil {
		return nil, nil
	}
	return io.ReadAll(r.Body)
}

func applyUpstreamOverrides(req *http.Request, src *http.Request) {
	if contentType := strings.TrimSpace(src.Header.Get("X-Upstream-Content-Type")); contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if accept := strings.TrimSpace(src.Header.Get("X-Upstream-Accept")); accept != "" {
		req.Header.Set("Accept", accept)
	}
	if auth := strings.TrimSpace(src.Header.Get("X-Upstream-Authorization")); auth != "" {
		req.Header.Set("Authorization", auth)
	}
}

func doSessionRequest(r *http.Request, targetURL, username, password string, forceRefresh bool) (*http.Response, error) {
	session, err := getSessionForRoute(r, username, password, forceRefresh)
	if err != nil {
		return nil, err
	}
	req, err := newUpstreamRequest(r, targetURL)
	if err != nil {
		return nil, err
	}
	copyHeaders(req.Header, r.Header, true)
	applyUpstreamOverrides(req, r)
	req.Header.Del("Authorization")
	if session.CookieHeader != "" {
		req.Header.Set("Cookie", session.CookieHeader)
	}
	if session.CSRFToken != "" {
		req.Header.Set(session.CSRFHeader, session.CSRFToken)
	}
	if session.Referer != "" {
		req.Header.Set("Referer", session.Referer)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	return httpClient.Do(req)
}

func getSessionForRoute(r *http.Request, username, password string, forceRefresh bool) (CachedSession, error) {
	loginURL, err := resolveSessionLoginURL(r)
	if err != nil {
		return CachedSession{}, err
	}
	cacheKey := fmt.Sprintf("%s|%s", loginURL, username)
	cacheSecs := headerInt(r, "X-Session-Cache-Seconds", 1800)

	cacheLock.Lock()
	if cached, found := sessionCache[cacheKey]; found && !forceRefresh && time.Now().Before(cached.Expiry) {
		cacheLock.Unlock()
		return cached, nil
	}
	cacheLock.Unlock()

	session, err := loginSession(r, loginURL, username, password, cacheSecs)
	if err != nil {
		return CachedSession{}, err
	}

	cacheLock.Lock()
	sessionCache[cacheKey] = session
	cacheLock.Unlock()
	return session, nil
}

func resolveSessionLoginURL(r *http.Request) (string, error) {
	if loginURL := firstNonEmpty(r.Header.Get("X-Session-Login-URL"), os.Getenv("SESSION_LOGIN_URL")); loginURL != "" {
		return loginURL, nil
	}
	baseURL := firstNonEmpty(r.Header.Get("X-Upstream-Base-URL"), os.Getenv("UPSTREAM_BASE_URL"))
	if baseURL == "" {
		return "", fmt.Errorf("Missing X-Session-Login-URL or UPSTREAM_BASE_URL for session auth")
	}
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("Invalid upstream base URL: %w", err)
	}
	parsedBase.Path = strings.TrimRight(parsedBase.Path, "/") + "/login"
	parsedBase.RawQuery = ""
	return parsedBase.String(), nil
}

func loginSession(r *http.Request, loginURL, username, password string, cacheSecs int) (CachedSession, error) {
	contentType := firstNonEmpty(r.Header.Get("X-Session-Login-Content-Type"), os.Getenv("SESSION_LOGIN_CONTENT_TYPE"), "application/x-www-form-urlencoded")
	body := firstNonEmpty(r.Header.Get("X-Session-Login-Body"), os.Getenv("SESSION_LOGIN_BODY"))
	if body == "" {
		values := url.Values{}
		values.Set(firstNonEmpty(r.Header.Get("X-Session-Username-Field"), os.Getenv("SESSION_USERNAME_FIELD"), "username"), username)
		values.Set(firstNonEmpty(r.Header.Get("X-Session-Password-Field"), os.Getenv("SESSION_PASSWORD_FIELD"), "password"), password)
		body = values.Encode()
	} else {
		body = strings.ReplaceAll(body, "{{username}}", username)
		body = strings.ReplaceAll(body, "{{password}}", password)
	}

	req, err := http.NewRequest("POST", loginURL, strings.NewReader(body))
	if err != nil {
		return CachedSession{}, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return CachedSession{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return CachedSession{}, fmt.Errorf("session login failed: %s", resp.Status)
	}

	var cookieParts []string
	csrfToken := ""
	csrfCookieNames := splitList(firstNonEmpty(r.Header.Get("X-Session-CSRF-Cookie-Names"), os.Getenv("SESSION_CSRF_COOKIE_NAMES"), "csrftoken,csrf_token"))
	for _, cookie := range resp.Cookies() {
		cookieParts = append(cookieParts, cookie.Name+"="+cookie.Value)
		if containsFold(csrfCookieNames, cookie.Name) {
			csrfToken = cookie.Value
		}
	}
	csrfHeader := firstNonEmpty(r.Header.Get("X-Session-CSRF-Header"), os.Getenv("SESSION_CSRF_HEADER"), "X-CSRFToken")
	if csrfToken == "" {
		csrfToken = firstNonEmpty(resp.Header.Get(csrfHeader), resp.Header.Get("X-CSRF-Token"), resp.Header.Get("X-CSRFToken"))
	}
	if len(cookieParts) == 0 {
		return CachedSession{}, fmt.Errorf("session login did not return cookies")
	}

	return CachedSession{
		CookieHeader: strings.Join(cookieParts, "; "),
		CSRFToken:    csrfToken,
		CSRFHeader:   csrfHeader,
		Referer:      originFromURL(loginURL),
		Expiry:       time.Now().Add(time.Duration(cacheSecs) * time.Second),
	}, nil
}

func copyHeaders(dst http.Header, src http.Header, overrideAuthorization bool) {
	for name, values := range src {
		lower := strings.ToLower(name)
		if lower == "host" || lower == "content-length" || lower == "connection" ||
			lower == "keep-alive" || lower == "proxy-authenticate" || lower == "proxy-authorization" ||
			lower == "te" || lower == "trailers" || lower == "transfer-encoding" || lower == "upgrade" {
			continue
		}
		if overrideAuthorization && lower == "authorization" {
			continue
		}
		for _, v := range values {
			dst.Add(name, v)
		}
	}
}

func doUpstreamRequest(w http.ResponseWriter, req *http.Request, targetURL string) {
	start := time.Now()
	resp, err := httpClient.Do(req)
	duration := time.Since(start)
	log.Printf("[DEBUG] Upstream request duration: %v", duration)
	if err != nil || (resp != nil && resp.StatusCode == http.StatusGatewayTimeout) {
		log.Println("[WARN] First attempt failed (timeout or 504), retrying once...")
		startRetry := time.Now()
		resp, err = httpClient.Do(req)
		retryDuration := time.Since(startRetry)
		log.Printf("[DEBUG] Retry upstream request duration: %v", retryDuration)
	}
	if err != nil {
		log.Printf("[ERROR] Upstream request failed: %v", err)
		http.Error(w, "Upstream API error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	writeUpstreamResponse(w, resp, targetURL)
}

func writeUpstreamResponse(w http.ResponseWriter, resp *http.Response, targetURL string) {
	log.Printf("[INFO] Upstream response: %s (%d)", targetURL, resp.StatusCode)
	wHeader := w.Header()
	for k, v := range resp.Header {
		if strings.ToLower(k) == "content-encoding" && strings.Contains(strings.Join(v, ","), "gzip") {
			continue
		}
		for _, val := range v {
			wHeader.Add(k, val)
		}
	}
	w.WriteHeader(resp.StatusCode)
	var reader io.ReadCloser
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed to create gzip reader: %v", err)
			http.Error(w, "Failed to read gzip response", http.StatusInternalServerError)
			return
		}
		defer gzipReader.Close()
		reader = gzipReader
	} else {
		reader = resp.Body
	}
	if _, err := io.Copy(w, reader); err != nil {
		log.Printf("[ERROR] Failed to copy response body: %v", err)
	}
}

func getTokenForRoute(path, clientID, clientSecret, tokenURL, tokenField string, cacheSecs int) (string, error) {
	cacheKey := fmt.Sprintf("%s|%s|%s", path, clientID, clientSecret)

	cacheLock.Lock()
	defer cacheLock.Unlock()

	if cached, found := tokenCache[cacheKey]; found && time.Now().Before(cached.Expiry) {
		if debugMode {
			log.Printf("[DEBUG] Token cache hit for %s", maskString(clientID))
		}
		return cached.Token, nil
	}

	log.Printf("[INFO] Token cache miss. Fetching new token for %s", maskString(clientID))

	data := "grant_type=client_credentials"

	var resp *http.Response
	var lastErr error

	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data))
		if err != nil {
			return "", fmt.Errorf("build token request (attempt %d): %w", attempt, err)
		}
		req.SetBasicAuth(clientID, clientSecret)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err = httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("token request failed (attempt %d): %w", attempt, err)
			log.Printf("[WARN] %v", lastErr)
			time.Sleep(time.Duration(attempt*attempt) * time.Second)
			continue
		}

		defer resp.Body.Close()
		decoder := json.NewDecoder(resp.Body)
		var body map[string]interface{}
		if err := decoder.Decode(&body); err != nil {
			lastErr = fmt.Errorf("decode token response (attempt %d): %w", attempt, err)
			log.Printf("[WARN] %v", lastErr)
			time.Sleep(time.Duration(attempt*attempt) * time.Second)
			continue
		}

		if resp.StatusCode == http.StatusOK {
			if debugMode {
				log.Printf("[DEBUG] Token response body: %+v", body)
			}
			token, ok := body[tokenField].(string)
			if !ok || token == "" {
				lastErr = fmt.Errorf("missing token field %q", tokenField)
				log.Printf("[WARN] %v", lastErr)
				time.Sleep(time.Duration(attempt*attempt) * time.Second)
				continue
			}

			expiresIn, _ := body["expires_in"].(float64)
			if expiresIn == 0 {
				expiresIn = float64(cacheSecs)
			}

			tokenCache[cacheKey] = CachedToken{
				Token:  token,
				Expiry: time.Now().Add(time.Duration(expiresIn) * time.Second),
			}

			log.Printf("[INFO] New token fetched for %s (expires in %ds)", maskString(clientID), cacheSecs)
			return token, nil
		}

		lastErr = fmt.Errorf("unexpected status %d", resp.StatusCode)
		log.Printf("[WARN] Token response status not OK (attempt %d): %s", attempt, resp.Status)
		time.Sleep(time.Duration(attempt*attempt) * time.Second)
	}

	return "", fmt.Errorf("failed to retrieve token after retries: %w", lastErr)
}

func maskString(s string) string {
	if len(s) <= 4 {
		return "***"
	}
	return s[:2] + "***" + s[len(s)-2:]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func headerInt(r *http.Request, name string, fallback int) int {
	value := strings.TrimSpace(r.Header.Get(name))
	if value == "" {
		return fallback
	}
	var parsed int
	if _, err := fmt.Sscanf(value, "%d", &parsed); err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func originFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return parsed.Scheme + "://" + parsed.Host
}

func splitList(value string) []string {
	var result []string
	for _, part := range strings.Split(value, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func generateSelfSignedCert(certFile, keyFile string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"Self-Signed Proxy"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	keyOut, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return err
	}

	return nil
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// --- AWS SDK Generic Handler ---

func handleAWSRequestWithSDK(w http.ResponseWriter, r *http.Request, service string, action string) {
	ctx := context.Background()
	region := getRegionFromRequest(r)
	useProfile := shouldUseProfile(r)
	awsCreds, err := getAWSCredentialsFromRequest(r, useProfile)
	if err != nil {
		log.Printf("[ERROR] %v", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	// Handle optional role assumption
	roleToAssume := r.Header.Get("X-AWS-Role-To-Assume")
	if roleToAssume != "" {
		creds := credentials.NewStaticCredentialsProvider(awsCreds.AccessKeyID, awsCreds.SecretAccessKey, awsCreds.SessionToken)
		cfg, err := config.LoadDefaultConfig(ctx, config.WithCredentialsProvider(creds))
		if err != nil {
			log.Printf("[ERROR] Failed to load config for role assumption: %v", err)
			http.Error(w, "Failed to assume role", http.StatusInternalServerError)
			return
		}
		stsClient := sts.NewFromConfig(cfg)
		input := &sts.AssumeRoleInput{
			RoleArn:         &roleToAssume,
			RoleSessionName: aws.String("token-gateway-session"),
			DurationSeconds: aws.Int32(3600),
		}
		output, err := stsClient.AssumeRole(ctx, input)
		if err != nil {
			log.Printf("[ERROR] Failed to assume role: %v", err)
			http.Error(w, "Failed to assume role", http.StatusInternalServerError)
			return
		}
		credsOut := output.Credentials
		awsCreds = aws.Credentials{
			AccessKeyID:     *credsOut.AccessKeyId,
			SecretAccessKey: *credsOut.SecretAccessKey,
			SessionToken:    *credsOut.SessionToken,
			Source:          "AssumeRole",
			Expires:         *credsOut.Expiration,
		}
		log.Printf("[INFO] Assumed role %s successfully", roleToAssume)
	}

	credsProvider := credentials.NewStaticCredentialsProvider(
		awsCreds.AccessKeyID,
		awsCreds.SecretAccessKey,
		awsCreds.SessionToken,
	)
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credsProvider),
	)
	if err != nil {
		log.Printf("[ERROR] Failed to create AWS SDK config: %v", err)
		http.Error(w, "AWS SDK config error", http.StatusInternalServerError)
		return
	}

	client, err := buildAWSServiceClient(service, cfg)
	if err != nil {
		http.Error(w, fmt.Sprintf("Unsupported AWS service: %s", service), http.StatusNotImplemented)
		return
	}

	// Parse input parameters from POST body as JSON
	var params map[string]interface{}
	if r.Method == "POST" {
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&params); err != nil && err != io.EOF {
			http.Error(w, "Invalid JSON parameters", http.StatusBadRequest)
			return
		}
	} else {
		params = make(map[string]interface{})
	}

	result, err := invokeAWSAction(ctx, client, action, params)
	if err != nil {
		log.Printf("[ERROR] AWS SDK call failed: %v", err)
		http.Error(w, fmt.Sprintf("AWS SDK call failed: %v", err), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(result); err != nil {
		log.Printf("[ERROR] Failed to write AWS JSON response body: %v", err)
	}
}

func getRegionFromRequest(r *http.Request) string {
	if reg := r.Header.Get("X-AWS-Region"); reg != "" {
		return reg
	}
	if reg := r.URL.Query().Get("Region"); reg != "" {
		return reg
	}
	return "us-east-1"
}

func shouldUseProfile(r *http.Request) bool {
	// Prefer X-Token-UseProfile header, fallback to X-AWS-Use-Instance-Profile
	return r.Header.Get("X-Token-UseProfile") == "1" || r.Header.Get("X-AWS-Use-Instance-Profile") == "1"
}

func getAWSCredentialsFromRequest(r *http.Request, useProfile bool) (aws.Credentials, error) {
	if useProfile {
		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			return aws.Credentials{}, fmt.Errorf("Failed to load instance profile credentials: %v", err)
		}
		creds, err := cfg.Credentials.Retrieve(context.Background())
		if err != nil {
			return aws.Credentials{}, fmt.Errorf("Failed to retrieve AWS credentials: %v", err)
		}
		return creds, nil
	}
	// Use BasicAuth or Authorization header
	username, password, ok := r.BasicAuth()
	if !ok {
		return aws.Credentials{}, fmt.Errorf("Missing or invalid basic auth")
	}
	var accessKeyID, secretOrToken string
	if username != "" {
		accessKeyID = username
		secretOrToken = password
	} else {
		accessKeyID = "apikey"
		secretOrToken = password
	}
	log.Printf("[INFO] Authenticated client: %s", maskString(accessKeyID))
	return aws.Credentials{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretOrToken,
	}, nil
}

func buildAWSServiceClient(service string, cfg aws.Config) (interface{}, error) {
	switch strings.ToLower(service) {
	case "ec2":
		return ec2.NewFromConfig(cfg), nil
	case "s3":
		return s3.NewFromConfig(cfg), nil
	case "sts":
		return sts.NewFromConfig(cfg), nil
	default:
		return nil, fmt.Errorf("unsupported AWS service: %s", service)
	}
}

func invokeAWSAction(ctx context.Context, client interface{}, action string, params map[string]interface{}) ([]byte, error) {
	clientVal := reflect.ValueOf(client)
	method := clientVal.MethodByName(action)
	if !method.IsValid() {
		// Try upper-case first letter
		actionTitle := strings.Title(action)
		method = clientVal.MethodByName(actionTitle)
	}
	if !method.IsValid() {
		// Try capitalize first letter, rest as-is
		if len(action) > 0 {
			actionCap := strings.ToUpper(string(action[0])) + action[1:]
			method = clientVal.MethodByName(actionCap)
		}
	}
	if !method.IsValid() {
		return nil, fmt.Errorf("unsupported action for service: %s", action)
	}
	// Build the input struct for the action
	methodType := method.Type()
	var in []reflect.Value
	// Most AWS SDK v2 methods have signature (context.Context, *InputType, ...opts) (OutputType, error)
	if methodType.NumIn() >= 2 {
		// First arg: context.Context
		in = append(in, reflect.ValueOf(ctx))
		// Second arg: pointer to input struct
		inputType := methodType.In(1)
		inputPtr := reflect.New(inputType.Elem())
		// Populate fields from params map
		if len(params) > 0 {
			inputJSON, err := json.Marshal(params)
			if err != nil {
				return nil, fmt.Errorf("Failed to marshal params: %v", err)
			}
			if err := json.Unmarshal(inputJSON, inputPtr.Interface()); err != nil {
				return nil, fmt.Errorf("Failed to decode params into input struct: %v", err)
			}
		}
		in = append(in, inputPtr)
		// Add any extra options as zero values (not supported for now)
	}
	// Call the method
	results := method.Call(in)
	if len(results) != 2 {
		return nil, fmt.Errorf("unexpected number of results from SDK method")
	}
	out := results[0].Interface()
	errVal := results[1]
	if !errVal.IsNil() {
		return nil, errVal.Interface().(error)
	}
	// Marshal output to JSON
	outJSON, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal SDK output: %v", err)
	}
	return outJSON, nil
}

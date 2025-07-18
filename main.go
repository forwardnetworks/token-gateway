package main

import (
	"compress/gzip"
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
	"os"
	"strings"
	"sync"
	"time"
)

var (
	listenAddress = ":" + os.Getenv("PORT")
	tokenCache    = make(map[string]CachedToken)
	cacheLock     sync.Mutex
	debugMode     = os.Getenv("DEBUG") == "1"
	insecureTLS   = os.Getenv("ALLOW_INSECURE_TLS") == "1"

	httpClient = &http.Client{
		Timeout: 60 * time.Second,
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
	path := r.URL.Path

	// Dynamically reconstruct target URL from incoming request
	upstreamHost := r.Header.Get("X-Upstream-Host")
	if upstreamHost == "" {
		log.Printf("[ERROR] Missing X-Upstream-Host header")
		http.Error(w, "Missing X-Upstream-Host header", http.StatusBadRequest)
		return
	}
	targetURL := fmt.Sprintf("%s%s", upstreamHost, r.URL.RequestURI())

	if debugMode {
		log.Printf("[DEBUG] Incoming request: %s %s", r.Method, r.URL.String())
	}

	tokenURL := r.Header.Get("X-Token-URL")
	if tokenURL == "" {
		log.Printf("[ERROR] Missing X-Token-URL header")
		http.Error(w, "Missing X-Token-URL header", http.StatusBadRequest)
		return
	}
	tokenField := r.Header.Get("X-Token-Field")
	if tokenField == "" {
		tokenField = "access_token"
	}

	headerPrefix := r.Header.Get("X-Header-Prefix")
	if headerPrefix == "" {
		headerPrefix = "Bearer "
	}

	cacheSecs := 1800 // fallback only

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		log.Printf("[WARN] Missing or invalid basic auth")
		w.Header().Set("WWW-Authenticate", `Basic realm="OAuth2 Proxy"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	log.Printf("[INFO] Authenticated client: %s", maskString(clientID))

	token, err := getTokenForRoute(path, clientID, clientSecret, tokenURL, tokenField, cacheSecs)
	if err != nil {
		log.Printf("[ERROR] Token retrieval failed: %v", err)
		http.Error(w, "Failed to retrieve token", http.StatusBadGateway)
		return
	}

	if targetURL == "" {
		log.Printf("[ERROR] Missing X-Upstream-URL header")
		http.Error(w, "Missing X-Upstream-URL header", http.StatusBadRequest)
		return
	}
	log.Printf("[INFO] Target URL: %s", targetURL)

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		log.Printf("[ERROR] Failed to build upstream request: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	for name, values := range r.Header {
		if strings.ToLower(name) == "authorization" {
			continue
		}
		for _, v := range values {
			req.Header.Add(name, v)
			if debugMode {
				log.Printf("[DEBUG] Forwarding header: %s: %s", name, v)
			}
		}
	}
	req.Header.Set("Authorization", headerPrefix+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("[ERROR] Upstream request failed: %v", err)
		http.Error(w, "Upstream API error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	log.Printf("[INFO] Upstream response: %s (%d)", targetURL, resp.StatusCode)

	wHeader := w.Header()
	for k, v := range resp.Header {
		if strings.ToLower(k) == "content-encoding" && strings.Contains(strings.Join(v, ","), "gzip") {
			// Strip gzip encoding before sending to client
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

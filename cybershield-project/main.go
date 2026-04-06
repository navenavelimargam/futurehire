package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// --- Structs for Nested Config ---
type Config struct {
	Server struct {
		Port       int    `json:"port"`
		BackendURL string `json:"backend_url"`
	} `json:"server"`
	RateLimits []struct {
		Path          string  `json:"path"`
		Method        string  `json:"method"`
		Limit         float64 `json:"limit"`
		WindowSeconds int     `json:"window_seconds"`
	} `json:"rate_limits"`
	Security struct {
		BlockSQLInjection bool     `json:"block_sql_injection"`
		BlacklistedIPs    []string `json:"blacklisted_ips"`
	} `json:"security"`
}

type LogEntry struct {
	IP       string `json:"IP"`
	Endpoint string `json:"Endpoint"`
	Method   string `json:"Method"`
	Status   string `json:"Status"`
	Reason   string `json:"Reason"`
	Time     string `json:"Time"`
}

type TokenBucket struct {
	tokens     float64
	lastUpdate time.Time
	mu         sync.Mutex
}

var (
	config       Config
	configMu     sync.RWMutex
	logs         []LogEntry
	logsMu       sync.RWMutex
	buckets      = make(map[string]*TokenBucket)
	bucketsMu    sync.Mutex
	requestCount int64
	currentRPS   float64
)

func (b *TokenBucket) Allow(limit float64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.lastUpdate).Seconds()
	b.tokens += elapsed * limit
	if b.tokens > 5 {
		b.tokens = 5
	} // Max Burst
	b.lastUpdate = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func loadConfig() {
	configMu.Lock()
	defer configMu.Unlock()
	file, _ := os.ReadFile("config.json")
	json.Unmarshal(file, &config)
}

func logEntry(ip, path, method, status, reason string) {
	logsMu.Lock()
	defer logsMu.Unlock()
	logs = append(logs, LogEntry{IP: ip, Endpoint: path, Method: method, Status: status, Reason: reason, Time: time.Now().Format("15:04:05")})
	if len(logs) > 50 {
		logs = logs[1:]
	}
}

func proxyHandler(proxy *httputil.ReverseProxy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/dashboard") || r.URL.Path == "/metrics" || r.URL.Path == "/api/blacklist" {
			return
		}

		atomic.AddInt64(&requestCount, 1)
		clientIP := strings.Split(r.RemoteAddr, ":")[0]
		if clientIP == "[" || clientIP == "::1" {
			clientIP = "127.0.0.1"
		}

		configMu.RLock()
		isBanned := slices.Contains(config.Security.BlacklistedIPs, clientIP)
		configMu.RUnlock()

		if isBanned {
			logEntry(clientIP, r.URL.Path, r.Method, "Blocked", "Banned IP Access")
			http.Error(w, "Forbidden: IP Banned", 403)
			return
		}

		// WAF Check
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(body))
		bodyStr := strings.ToLower(string(body))
		if strings.Contains(bodyStr, "1=1") || strings.Contains(bodyStr, "<script>") {
			logEntry(clientIP, r.URL.Path, r.Method, "Blocked", "WAF Detection")
			http.Error(w, "Threat Detected", 403)
			return
		}

		// Rate Limiting Logic
		key := clientIP + r.URL.Path
		bucketsMu.Lock()
		bucket, ok := buckets[key]
		if !ok {
			bucket = &TokenBucket{tokens: 5, lastUpdate: time.Now()}
			buckets[key] = bucket
		}
		bucketsMu.Unlock()

		if !bucket.Allow(2.0) {
			logEntry(clientIP, r.URL.Path, r.Method, "Blocked", "Rate Limit Hit")
			http.Error(w, "Too Many Requests", 429)
			return
		}

		logEntry(clientIP, r.URL.Path, r.Method, "Allowed", "Pass")
		proxy.ServeHTTP(w, r)
	}
}

func main() {
	loadConfig()

	go func() {
		for {
			prev := atomic.LoadInt64(&requestCount)
			time.Sleep(time.Second)
			currentRPS = float64(atomic.LoadInt64(&requestCount) - prev)
		}
	}()

	target, _ := url.Parse(config.Server.BackendURL)
	proxy := httputil.NewSingleHostReverseProxy(target)

	fs := http.FileServer(http.Dir("static"))
	http.Handle("/dashboard/", http.StripPrefix("/dashboard/", fs))

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		logsMu.RLock()
		defer logsMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"logs": logs, "rps": currentRPS, "config": config, "totalRequests": atomic.LoadInt64(&requestCount),
		})
	})

	http.HandleFunc("/api/blacklist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var req struct {
				IP string `json:"ip"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			configMu.Lock()
			config.Security.BlacklistedIPs = append(config.Security.BlacklistedIPs, req.IP)
			configMu.Unlock()
			logEntry(req.IP, "SYSTEM", "POST", "BANNED", "Manual Block")
			w.WriteHeader(http.StatusOK)
		}
	})

	http.HandleFunc("/", proxyHandler(proxy))

	fmt.Printf("🛡️  SecureShield Active on :%d\n", config.Server.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.Server.Port), nil))
}

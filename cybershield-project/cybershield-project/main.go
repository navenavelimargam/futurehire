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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// --- Structs ---
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
		HoneyTokens       []string `json:"honey_tokens"`
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

type ThreatEntry struct {
	IP    string `json:"ip"`
	Score int    `json:"score"`
}

type BenchMetric struct {
	Side    string `json:"side"`
	Latency int64  `json:"latency"`
	Time    int64  `json:"time"`
}

type BenchHub struct {
	mu      sync.Mutex
	clients map[chan BenchMetric]struct{}
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

	permanentBlacklist sync.Map
	securityLevel      int32
	threatScores       sync.Map
	benchmarkMode      = "CyberShield"
	benchModeMu        sync.RWMutex
	benchHub           = &BenchHub{clients: make(map[chan BenchMetric]struct{})}

	honeyTokenPaths = map[string]bool{
		"/v1/admin/config-backup": true,
		"/api/internal/user-dump": true,
		"/.env":                   true,
		"/admin/passwd":           true,
		"/wp-admin/setup-config":  true,
	}
)

func (b *TokenBucket) Allow(limit float64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.lastUpdate).Seconds()
	b.tokens += elapsed * limit
	if b.tokens > 5 {
		b.tokens = 5
	}
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
	if len(logs) > 100 {
		logs = logs[1:]
	}
}

func addThreatScore(ip string, points int) {
	val, _ := threatScores.LoadOrStore(ip, 0)
	newScore := val.(int) + points
	threatScores.Store(ip, newScore)
	if newScore >= 100 {
		permanentBlacklist.Store(ip, true)
		logEntry(ip, "SYSTEM", "AUTO", "BANNED", fmt.Sprintf("Threat score %d/100 — auto-blacklisted", newScore))
	}
}

func honeyTokenCheck(ip, path string) bool {
	if honeyTokenPaths[path] {
		permanentBlacklist.Store(ip, true)
		threatScores.Store(ip, 100)
		logEntry(ip, path, "GET", "BANNED", "Honey-Token Triggered")
		return true
	}
	return false
}

func extractAlertMessage(payload string) string {
	idx := strings.Index(strings.ToLower(payload), "alert(")
	if idx == -1 {
		return "alert message is not provided"
	}

	sub := payload[idx+len("alert("):]
	end := strings.Index(sub, ")")
	if end == -1 {
		return "alert message is not provided"
	}

	msg := strings.TrimSpace(sub[:end])
	msg = strings.Trim(msg, "\"' ")
	if msg == "" {
		return "alert message is not provided"
	}
	return msg
}

func (h *BenchHub) broadcast(m BenchMetric) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- m:
		default:
		}
	}
}

func (h *BenchHub) subscribe() chan BenchMetric {
	ch := make(chan BenchMetric, 10)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *BenchHub) unsubscribe(ch chan BenchMetric) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
}

func proxyHandler(proxy *httputil.ReverseProxy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/dashboard") ||
			r.URL.Path == "/metrics" ||
			r.URL.Path == "/api/blacklist" ||
			r.URL.Path == "/api/set-level" ||
			r.URL.Path == "/api/top-threats" ||
			r.URL.Path == "/api/set-benchmark" ||
			r.URL.Path == "/api/bench-stream" {
			return
		}

		start := time.Now()
		atomic.AddInt64(&requestCount, 1)
		clientIP := strings.Split(r.RemoteAddr, ":")[0]
		if clientIP == "[" || clientIP == "::1" {
			clientIP = "127.0.0.1"
		}

		// Honey-token check (always block)
		if honeyTokenCheck(clientIP, r.URL.Path) {
			http.Error(w, "Block: Honey token activated", 403)
			return
		}

		// WAF Check (always block if detected)
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(body))
		origBody := string(body)
		bodyStr := strings.ToLower(origBody)
		urlStr := strings.ToLower(r.URL.RawQuery)

		if strings.Contains(bodyStr, "<script>") || strings.Contains(bodyStr, "alert(") ||
			strings.Contains(urlStr, "<script>") || strings.Contains(urlStr, "alert(") {
			msg := extractAlertMessage(origBody)
			addThreatScore(clientIP, 40)
			logEntry(clientIP, r.URL.Path, r.Method, "Blocked", fmt.Sprintf("XSS Attack Detected (%s)", msg))
			http.Error(w, fmt.Sprintf("Block: XSS payload blocked — %s", msg), 403)
			return
		}

		if strings.Contains(bodyStr, "1=1") || strings.Contains(bodyStr, "1'='1") || strings.Contains(bodyStr, "1\"=\"1") ||
			strings.Contains(bodyStr, "or 1=1") || strings.Contains(bodyStr, "or '1'='1") || strings.Contains(bodyStr, "or+1=1") ||
			strings.Contains(bodyStr, "union select") || strings.Contains(bodyStr, "union+select") ||
			strings.Contains(urlStr, "1=1") || strings.Contains(urlStr, "1'='1") || strings.Contains(urlStr, "or 1=1") ||
			strings.Contains(urlStr, "or '1'='1") || strings.Contains(urlStr, "or+1=1") || strings.Contains(urlStr, "union select") ||
			strings.Contains(urlStr, "union+select") {
			addThreatScore(clientIP, 40)
			logEntry(clientIP, r.URL.Path, r.Method, "Blocked", "SQL Injection Attempt")
			latency := time.Since(start).Milliseconds()
			benchHub.broadcast(BenchMetric{Side: mode, Latency: latency, Time: time.Now().Unix()})
			http.Error(w, "Block: SQL injection payload blocked", 403)
			return
		}

		ua := strings.ToLower(r.Header.Get("User-Agent"))
		if strings.Contains(ua, "sqlmap") || strings.Contains(ua, "nikto") ||
			strings.Contains(ua, "masscan") || strings.Contains(ua, "nmap") {
			addThreatScore(clientIP, 15)
			logEntry(clientIP, r.URL.Path, r.Method, "Blocked", "Suspicious User-Agent")
			http.Error(w, "Block: Suspicious User-Agent", 403)
			return
		}

		if _, banned := permanentBlacklist.Load(clientIP); banned {
			logEntry(clientIP, r.URL.Path, r.Method, "Blocked", "Permanent Blacklist")
			http.Error(w, "Block: Permanent Blacklist", 403)
			return
		}

		configMu.RLock()
		isBanned := slices.Contains(config.Security.BlacklistedIPs, clientIP)
		configMu.RUnlock()
		if isBanned {
			logEntry(clientIP, r.URL.Path, r.Method, "Blocked", "Banned IP Access")
			http.Error(w, "Block: Banned IP Access", 403)
			return
		}

		level := atomic.LoadInt32(&securityLevel)

		benchModeMu.RLock()
		mode := benchmarkMode
		benchModeMu.RUnlock()

		if mode == "Legacy" {
			time.Sleep(150 * time.Millisecond)
			latency := time.Since(start).Milliseconds()
			benchHub.broadcast(BenchMetric{Side: "Legacy", Latency: latency, Time: time.Now().Unix()})
			logEntry(clientIP, r.URL.Path, r.Method, "Allowed", "Legacy Pass (no checks)")
			proxy.ServeHTTP(w, r)
			return
		}

		// Monitor mode — log only, but blocks already happened above
		if level == 0 {
			logEntry(clientIP, r.URL.Path, r.Method, "Monitor", "Observe Only")
			latency := time.Since(start).Milliseconds()
			benchHub.broadcast(BenchMetric{Side: "CyberShield", Latency: latency, Time: time.Now().Unix()})
			proxy.ServeHTTP(w, r)
			return
		}

		// Active/Lockdown mode
		rateLimit := 2.0
		if level == 2 {
			rateLimit = 0.4
		}

		key := clientIP + r.URL.Path
		bucketsMu.Lock()
		bucket, ok := buckets[key]
		if !ok {
			bucket = &TokenBucket{tokens: 5, lastUpdate: time.Now()}
			buckets[key] = bucket
		}
		bucketsMu.Unlock()

		if !bucket.Allow(rateLimit) {
			addThreatScore(clientIP, 20)
			logEntry(clientIP, r.URL.Path, r.Method, "Blocked", "Rate Limit Hit")
			http.Error(w, "Block: Rate Limit Hit", 429)
			return
		}

		latency := time.Since(start).Milliseconds()
		benchHub.broadcast(BenchMetric{Side: "CyberShield", Latency: latency, Time: time.Now().Unix()})
		logEntry(clientIP, r.URL.Path, r.Method, "Allowed", "Pass")
		proxy.ServeHTTP(w, r)
	}
}

func main() {
	loadConfig()

	for _, p := range config.Security.HoneyTokens {
		honeyTokenPaths[p] = true
	}

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

		blocked := 0
		honeyHits := 0
		for _, l := range logs {
			if l.Status == "Blocked" || l.Status == "BANNED" {
				blocked++
			}
			if strings.Contains(l.Reason, "Honey-Token") {
				honeyHits++
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"logs":          logs,
			"rps":           currentRPS,
			"config":        config,
			"totalRequests": atomic.LoadInt64(&requestCount),
			"blocked":       blocked,
			"honeyHits":     honeyHits,
			"securityLevel": atomic.LoadInt32(&securityLevel),
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
			permanentBlacklist.Store(req.IP, true)
			logEntry(req.IP, "SYSTEM", "POST", "BANNED", "Manual Block")
			w.WriteHeader(http.StatusOK)
		}
	})

	http.HandleFunc("/api/set-level", func(w http.ResponseWriter, r *http.Request) {
		lvl := r.URL.Query().Get("level")
		switch lvl {
		case "0":
			atomic.StoreInt32(&securityLevel, 0)
		case "1":
			atomic.StoreInt32(&securityLevel, 1)
		case "2":
			atomic.StoreInt32(&securityLevel, 2)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int32{"level": atomic.LoadInt32(&securityLevel)})
	})

	http.HandleFunc("/api/top-threats", func(w http.ResponseWriter, r *http.Request) {
		var threats []ThreatEntry
		threatScores.Range(func(k, v interface{}) bool {
			threats = append(threats, ThreatEntry{IP: k.(string), Score: v.(int)})
			return true
		})
		sort.Slice(threats, func(i, j int) bool {
			return threats[i].Score > threats[j].Score
		})
		n := len(threats)
		if n > 10 {
			n = 10
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(threats[:n])
	})

	http.HandleFunc("/api/set-benchmark", func(w http.ResponseWriter, r *http.Request) {
		mode := r.URL.Query().Get("mode")
		if mode == "Legacy" || mode == "CyberShield" {
			benchModeMu.Lock()
			benchmarkMode = mode
			benchModeMu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		benchModeMu.RLock()
		json.NewEncoder(w).Encode(map[string]string{"mode": benchmarkMode})
		benchModeMu.RUnlock()
	})

	http.HandleFunc("/api/bench-stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		ch := benchHub.subscribe()
		defer benchHub.unsubscribe(ch)

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		for {
			select {
			case m := <-ch:
				data, _ := json.Marshal(m)
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})

	http.HandleFunc("/api/ping-bench", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong"))
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			http.Redirect(w, r, "/dashboard/", http.StatusFound)
			return
		}
		proxyHandler(proxy)(w, r)
	})

	fmt.Printf("🛡️  CyberShield Active on :%d\n", config.Server.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.Server.Port), nil))
}

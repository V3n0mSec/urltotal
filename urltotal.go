package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const version = "1.0.0"

/* ===================== BANNER ===================== */

func banner() {
	fmt.Println(`
 _   _ ____  _     _____ ____  _____  _    
| | | |  _ \| |   |_   _/ ___||_   _|/ \   
| | | | |_) | |     | | \___ \  | | / _ \  
| |_| |  _ <| |___  | |  ___) | | |/ ___ \ 
 \___/|_| \_\_____| |_| |____/  |_/_/   \_\

URLTOTAL v1.0.0
Passive URL & Domain Intelligence
(VirusTotal + urlscan.io)
`)
}

/* ===================== ROTATOR ===================== */

type Rotator struct {
	keys []string
	i    int
	mu   sync.Mutex
}

func (r *Rotator) Next() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.keys) == 0 {
		return ""
	}
	k := r.keys[r.i%len(r.keys)]
	r.i++
	return k
}

func splitEnv(name string) []string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := []string{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

/* ===================== GLOBALS ===================== */

var (
	vtV2Rot = &Rotator{keys: splitEnv("VT_V2_KEYS")}
	vtV3Rot = &Rotator{keys: splitEnv("VT_V3_KEYS")}
	usRot   = &Rotator{keys: splitEnv("URLSCAN_KEYS")}

	domains sync.Map
	ips     sync.Map
	urlsSet sync.Map
	paths   sync.Map
	params  sync.Map

	client = &http.Client{Timeout: 25 * time.Second}
)

/* ===================== HELPERS ===================== */

func isIP(s string) bool {
	return net.ParseIP(s) != nil
}

// 🔴 ORWA: DO NOT STRIP SCHEME
func cleanInput(s string) string {
	return strings.TrimSpace(strings.TrimRight(s, "/"))
}

func addDomain(d string) {
	if d != "" {
		domains.Store(d, true)
	}
}

func addIP(ip string) {
	if ip != "" {
		ips.Store(ip, true)
	}
}

// 🔴 ORWA RULE: STORE RAW URL FIRST
func addURL(raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}

	// RAW URL — untouched
	urlsSet.Store(raw, true)

	// Best-effort parsing ONLY for side lists
	u, err := url.Parse(raw)
	if err != nil {
		return
	}

	if u.Hostname() != "" {
		addDomain(u.Hostname())
	}
	if u.Path != "" && u.Path != "/" {
		paths.Store(u.Path, true)
	}
	for p := range u.Query() {
		params.Store(p, true)
	}
}

/* ===================== VIRUSTOTAL V2 ===================== */

func vtV2Domain(domain string) {
	key := vtV2Rot.Next()
	if key == "" {
		return
	}

	endpoint := fmt.Sprintf(
		"https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s",
		key, domain,
	)

	resp, err := client.Get(endpoint)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var data map[string]any
	json.NewDecoder(resp.Body).Decode(&data)

	for _, field := range []string{"undetected_urls", "detected_urls"} {
		if arr, ok := data[field].([]any); ok {
			for _, it := range arr {
				if row, ok := it.([]any); ok && len(row) > 0 {
					if u, ok := row[0].(string); ok {
						addURL(u)
					}
				}
			}
		}
	}

	if res, ok := data["resolutions"].([]any); ok {
		for _, r := range res {
			if m, ok := r.(map[string]any); ok {
				if ip, ok := m["ip_address"].(string); ok {
					addIP(ip)
				}
			}
		}
	}
}

func vtV2IP(ip string) {
	key := vtV2Rot.Next()
	if key == "" {
		return
	}

	endpoint := fmt.Sprintf(
		"https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=%s&ip=%s",
		key, ip,
	)

	resp, err := client.Get(endpoint)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var data map[string]any
	json.NewDecoder(resp.Body).Decode(&data)

	if res, ok := data["resolutions"].([]any); ok {
		for _, r := range res {
			if m, ok := r.(map[string]any); ok {
				if h, ok := m["hostname"].(string); ok {
					addDomain(h)
				}
			}
		}
	}
}

/* ===================== VIRUSTOTAL V3 ===================== */

func vtV3Subdomains(domain string) {
	key := vtV3Rot.Next()
	if key == "" {
		return
	}

	req, _ := http.NewRequest(
		"GET",
		fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=100", domain),
		nil,
	)
	req.Header.Set("x-apikey", key)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var data map[string]any
	json.NewDecoder(resp.Body).Decode(&data)

	if arr, ok := data["data"].([]any); ok {
		for _, it := range arr {
			if m, ok := it.(map[string]any); ok {
				if id, ok := m["id"].(string); ok {
					addDomain(id)
				}
			}
		}
	}
}

/* ===================== URLSCAN ===================== */

func urlscan(domain string) {
	key := usRot.Next()
	if key == "" {
		return
	}

	req, _ := http.NewRequest(
		"GET",
		fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s", domain),
		nil,
	)
	req.Header.Set("API-Key", key)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var data map[string]any
	json.NewDecoder(resp.Body).Decode(&data)

	if res, ok := data["results"].([]any); ok {
		for _, r := range res {
			if m, ok := r.(map[string]any); ok {
				if p, ok := m["page"].(map[string]any); ok {
					if u, ok := p["url"].(string); ok {
						addURL(u)
					}
					if ip, ok := p["ip"].(string); ok {
						addIP(ip)
					}
				}
			}
		}
	}
}

/* ===================== CORE ===================== */

func processTarget(t string) {
	t = cleanInput(t)

	if isIP(t) {
		addIP(t)
		vtV2IP(t)
		return
	}

	addDomain(t)
	vtV2Domain(t)
	vtV3Subdomains(t)
	urlscan(t)
}

/* ===================== OUTPUT ===================== */

func writeSet(path string, m *sync.Map) {
	f, _ := os.Create(path)
	defer f.Close()

	w := bufio.NewWriter(f)
	m.Range(func(k, _ any) bool {
		fmt.Fprintln(w, k.(string))
		return true
	})
	w.Flush()
}

/* ===================== MAIN ===================== */

func main() {
	var input, file, out string
	var workers int

	flag.StringVar(&input, "i", "", "single target (domain, subdomain, IP)")
	flag.StringVar(&file, "f", "", "file with targets")
	flag.StringVar(&out, "o", ".", "output directory")
	flag.IntVar(&workers, "w", 8, "number of workers")
	flag.Parse()

	banner()

	var targets []string

	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			fmt.Println("Failed to open file")
			return
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			targets = append(targets, sc.Text())
		}
		f.Close()
	} else if input != "" {
		targets = append(targets, input)
	} else {
		fmt.Println("Usage: urltotal -i domain | -f file")
		return
	}

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(x string) {
			defer wg.Done()
			processTarget(x)
			<-sem
		}(t)
	}
	wg.Wait()

	os.MkdirAll(out, 0755)
	writeSet(filepath.Join(out, "domains.txt"), &domains)
	writeSet(filepath.Join(out, "ips.txt"), &ips)
	writeSet(filepath.Join(out, "urls.txt"), &urlsSet)
	writeSet(filepath.Join(out, "paths.txt"), &paths)
	writeSet(filepath.Join(out, "params.txt"), &params)
}

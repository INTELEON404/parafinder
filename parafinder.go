package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

const (
	Version   = "3.9"
	Author    = "INTELEON404"
	FuzzKey   = "FUZZ"
)

type Provider interface {
	Name() string
	Execute(ctx context.Context, target string, results chan<- Result) error
}

type Middleware interface {
	Name() string
	Process(res *Result) bool
}

type Output interface {
	Write(res Result) error
	Close() error
}

type Result struct {
	Timestamp  time.Time `json:"timestamp"`
	Source     string    `json:"source"`
	URL        string    `json:"url"`
	Host       string    `json:"host"`
	Fuzzed     string    `json:"fuzzed,omitempty"`
	ParamCount int       `json:"param_count"`
}

type Options struct {
	Targets    []string
	Threads    int
	RateLimit  int
	Proxy      string
	Tor        bool
	GF         string
	Fuzz       bool
	JSON       bool
	Silent     bool
	Verbose    bool
	OutputFile string
	Timeout    int
	MinParams  int
}

type Stats struct {
	Total    uint64
	Unique   uint64
	Filtered uint64
	mu       sync.Mutex
	Start    time.Time
}

type Engine struct {
	Opt        *Options
	Providers  []Provider
	Middlewares []Middleware
	Outputs    []Output
	HttpClient *http.Client
	RateLimiter *rate.Limiter
	seen       sync.Map
	stats      *Stats
}

func NewEngine(opt *Options) *Engine {
	if opt.Tor {
		opt.Proxy = "socks5://127.0.0.1:9050"
	}

	var proxy func(*http.Request) (*url.URL, error)
	if opt.Proxy != "" {
		if pu, err := url.Parse(opt.Proxy); err == nil {
			proxy = http.ProxyURL(pu)
		}
	}

	tr := &http.Transport{
		Proxy:                 proxy,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		DialContext:           (&net.Dialer{Timeout: time.Duration(opt.Timeout) * time.Second}).DialContext,
		MaxIdleConns:          180,
		MaxConnsPerHost:       40,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
	}

	return &Engine{
		Opt: opt,
		HttpClient: &http.Client{
			Transport: tr,
			Timeout:   time.Duration(opt.Timeout+5) * time.Second,
		},
		RateLimiter: rate.NewLimiter(rate.Every(time.Second/time.Duration(opt.RateLimit)), opt.RateLimit*2),
		stats:       &Stats{Start: time.Now()},
	}
}

func (e *Engine) incTotal()    { e.stats.mu.Lock(); e.stats.Total++; e.stats.mu.Unlock() }
func (e *Engine) incUnique()   { e.stats.mu.Lock(); e.stats.Unique++; e.stats.mu.Unlock() }
func (e *Engine) incFiltered() { e.stats.mu.Lock(); e.stats.Filtered++; e.stats.mu.Unlock() }

func (e *Engine) Run(ctx context.Context) error {
	results  := make(chan Result, 8192)
	filtered := make(chan Result, 4096)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(20) // limit concurrent provider HTTP requests

	for _, target := range e.Opt.Targets {
		target := target // capture
		for _, prov := range e.Providers {
			prov := prov
			g.Go(func() error {
				return prov.Execute(ctx, target, results)
			})
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < e.Opt.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for res := range results {
				e.incTotal()

				if !e.markSeen(res.URL) {
					continue
				}
				e.incUnique()

				parsed, _ := url.Parse(res.URL)
				res.ParamCount = len(parsed.Query())

				if res.ParamCount < e.Opt.MinParams {
					continue
				}

				keep := true
				for _, m := range e.Middlewares {
					if !m.Process(&res) {
						keep = false
						break
					}
				}
				if !keep {
					continue
				}

				e.incFiltered()

				if e.Opt.Fuzz {
					e.applyFuzz(&res)
				}

				select {
				case filtered <- res:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		_ = g.Wait()
		close(results)
		wg.Wait()
		close(filtered)
	}()

	for res := range filtered {
		for _, out := range e.Outputs {
			_ = out.Write(res)
		}
	}

	return g.Wait()
}

func (e *Engine) markSeen(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}

	var sb strings.Builder
	sb.Grow(256)
	sb.WriteString(u.Host)
	sb.WriteString(u.EscapedPath())
	sb.WriteByte('?')

	keys := make([]string, 0, 24)
	for k := range u.Query() {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i, k := range keys {
		if i > 0 {
			sb.WriteByte('|')
		}
		sb.WriteString(k)
	}

	_, loaded := e.seen.LoadOrStore(sb.String(), struct{}{})
	return !loaded
}

func (e *Engine) applyFuzz(res *Result) {
	u, err := url.Parse(res.URL)
	if err != nil {
		return
	}
	q := u.Query()
	for k := range q {
		q.Set(k, FuzzKey)
	}
	u.RawQuery = q.Encode()
	res.Fuzzed = u.String()
}

func (e *Engine) PrintStats() {
	if e.Opt.Silent {
		return
	}
	dur := time.Since(e.stats.Start).Round(time.Second)
	fmt.Fprintf(os.Stderr, "\n\033[32m[+] Scan finished\033[0m  Duration: %v\n", dur)
	fmt.Fprintf(os.Stderr, "  Total:    %d\n", e.stats.Total)
	fmt.Fprintf(os.Stderr, "  Unique:   %d\n", e.stats.Unique)
	fmt.Fprintf(os.Stderr, "  Filtered: %d\n", e.stats.Filtered)
}

// ─────────────────────────────────────────────────────────────────────────────
// Providers (fixed versions)
// ─────────────────────────────────────────────────────────────────────────────

type WaybackProvider struct{ Client *http.Client }
func (p *WaybackProvider) Name() string { return "Wayback" }
func (p *WaybackProvider) Execute(ctx context.Context, target string, ch chan<- Result) error {
	api := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=txt&fl=original&collapse=urlkey&filter=statuscode:200-399&limit=30000", url.QueryEscape(target))
	req, _ := http.NewRequestWithContext(ctx, "GET", api, nil)
	req.Header.Set("User-Agent", "ParaFinder/"+Version)

	resp, err := p.Client.Do(req)
	if err != nil {
		return fmt.Errorf("wayback: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("wayback status %d", resp.StatusCode)
	}

	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		u, err := url.Parse(line)
		if err != nil || u.RawQuery == "" {
			continue
		}
		ch <- Result{Timestamp: time.Now(), Source: p.Name(), URL: line, Host: u.Host}
	}
	return sc.Err()
}

type CommonCrawlProvider struct{ Client *http.Client }
func (p *CommonCrawlProvider) Name() string { return "CommonCrawl" }

// Note: Real usage should fetch current index list first → https://index.commoncrawl.org/collinfo.json
func (p *CommonCrawlProvider) Execute(ctx context.Context, target string, ch chan<- Result) error {
	// Use more recent indices (update as needed — check https://index.commoncrawl.org/collinfo.json)
	indices := []string{
		"CC-MAIN-2025-50", // ← fictional 2026 example — replace with real ones
		"CC-MAIN-2025-08",
		"CC-MAIN-2024-51",
	}

	for _, idx := range indices {
		if err := ctx.Err(); err != nil {
			return err
		}
		api := fmt.Sprintf("https://index.commoncrawl.org/%s-index?url=*.%s/*&output=json", idx, url.QueryEscape(target))
		req, _ := http.NewRequestWithContext(ctx, "GET", api, nil)

		resp, err := p.Client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) != nil {
				continue
			}
			urlStr, _ := m["url"].(string)
			if urlStr == "" {
				continue
			}
			u, err := url.Parse(urlStr)
			if err != nil || u.RawQuery == "" {
				continue
			}
			ch <- Result{Timestamp: time.Now(), Source: p.Name(), URL: urlStr, Host: u.Host}
		}
	}
	return nil
}

type URLScanProvider struct{ Client *http.Client }
func (p *URLScanProvider) Name() string { return "URLScan" }
func (p *URLScanProvider) Execute(ctx context.Context, target string, ch chan<- Result) error {
	api := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=5000", url.QueryEscape(target))
	req, _ := http.NewRequestWithContext(ctx, "GET", api, nil)
	req.Header.Set("User-Agent", "ParaFinder/"+Version)

	resp, err := p.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var res struct {
		Results []struct {
			Page struct{ URL string `json:"url"` } `json:"page"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return err
	}

	for _, r := range res.Results {
		u, err := url.Parse(r.Page.URL)
		if err != nil || u.RawQuery == "" {
			continue
		}
		ch <- Result{Timestamp: time.Now(), Source: p.Name(), URL: r.Page.URL, Host: u.Host}
	}
	return nil
}

type AlienVaultProvider struct{ Client *http.Client }
func (p *AlienVaultProvider) Name() string { return "AlienVault" }
func (p *AlienVaultProvider) Execute(ctx context.Context, target string, ch chan<- Result) error {
	for page := 1; page <= 6; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		api := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=100&page=%d", url.QueryEscape(target), page)
		req, _ := http.NewRequestWithContext(ctx, "GET", api, nil)

		resp, err := p.Client.Do(req)
		if err != nil {
			return err
		}

		var data struct {
			Detail  string `json:"detail"`
			Results []struct {
				URL string `json:"url"`
			} `json:"results"`
			Pagination struct {
				Next string `json:"next"`
			} `json:"pagination"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			resp.Body.Close()
			return err
		}
		resp.Body.Close()

		if data.Detail != "" {
			break // error or rate limit
		}

		for _, item := range data.Results {
			u, err := url.Parse(item.URL)
			if err != nil || u.RawQuery == "" {
				continue
			}
			ch <- Result{Timestamp: time.Now(), Source: p.Name(), URL: item.URL, Host: u.Host}
		}

		if data.Pagination.Next == "" {
			break
		}
	}
	return nil
}

// VirusTotal disabled — needs API key + different structure
// If you want VT → add flag for API key and use /api/v3/domains/{domain}/communicating_files or similar

// ─────────────────────────────────────────────────────────────────────────────
// Middleware & Output (mostly unchanged)
// ─────────────────────────────────────────────────────────────────────────────

type GFMiddleware struct{ Pattern string }

func (m *GFMiddleware) Name() string { return "GF" }

func (m *GFMiddleware) Process(res *Result) bool {
	if m.Pattern == "" {
		return true
	}

	patterns := map[string]string{
		"ssrf":     `(?i)(url|redirect|dest|callback|host|uri|target|next|view|file|path|continue|return|data|reference|site|html|navigate)`,
		"xss":      `(?i)(q|search|id|lang|keyword|query|input|s|term|text|msg|name|p|page|comment|title|data|content|val)`,
		"sqli":     `(?i)(id|select|report|update|query|sort|limit|page|user|pass|pwd|order|by|where|table|column|search|cat)`,
		"lfi":      `(?i)(file|document|folder|root|path|pg|style|pdf|template|php_path|doc|page|name|cat|dir|action|board|date|detail|download|prefix|include|inc|locate|show|site|type|view|content|layout|mod|conf)`,
		"rce":      `(?i)(cmd|exec|command|execute|ping|query|jump|code|reg|do|func|arg|option|load|process|step|read|function|req|feature|exe|module|payload|run|print|daemon)`,
		"redirect": `(?i)(url|uri|redirect|next|target|rurl|dest|destination|redir|redirect_uri|redirect_url|return|returnTo|return_to|checkout_url|continue|return_path|image_url|go|out|view|dir|show|navigation|path|reference|site)`,
	}

	reStr, ok := patterns[strings.ToLower(m.Pattern)]
	if !ok {
		return true
	}

	match, _ := regexp.MatchString(reStr, res.URL)
	return match
}

type CLIOutput struct{ Silent, Verbose bool }
func (o *CLIOutput) Write(res Result) error {
	out := res.URL
	if res.Fuzzed != "" {
		out = res.Fuzzed
	}

	if o.Silent {
		fmt.Println(out)
	} else if o.Verbose {
		fmt.Printf("\033[34m[%s]\033[0m \033[33m[%d params]\033[0m %s\n", res.Source, res.ParamCount, out)
	} else {
		fmt.Printf("\033[34m[%s]\033[0m %s\n", res.Source, out)
	}
	return nil
}
func (o *CLIOutput) Close() error { return nil }

type FileOutput struct{ *bufio.Writer; JSON bool }
func (o *FileOutput) Write(res Result) error {
	var line string
	if o.JSON {
		b, _ := json.Marshal(res)
		line = string(b)
	} else {
		line = res.URL
		if res.Fuzzed != "" {
			line = res.Fuzzed
		}
	}
	_, err := o.WriteString(line + "\n")
	return err
}
func (o *FileOutput) Close() error {
	o.Flush()
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

func printBanner() {
	fmt.Fprintf(os.Stderr, "\033[35m"+
		` █▀█ ▄▀█ █▀█ ▄▀█ █▀▀ █ █▄░█ █▀▄ █▀▀ █▀█
 █▀▀ █▀█ █▀▄ █▀█ █▀░ █ █░▀█ █▄▀ ██▄ █▀▄
 PARAFINDER v%s | DEVELOPED BY %s
`+"\033[0m\n", Version, Author)
}

func main() {
	opt := &Options{}
	var domain string

	flag.StringVar(&domain, "d", "", "Single target domain")
	flag.StringVar(&opt.OutputFile, "o", "", "Output file")
	flag.IntVar(&opt.Threads, "t", 80, "Worker threads")
	flag.IntVar(&opt.RateLimit, "rl", 40, "Global rate limit/sec")
	flag.IntVar(&opt.Timeout, "timeout", 40, "HTTP timeout seconds")
	flag.IntVar(&opt.MinParams, "mp", 1, "Minimum parameter count filter")
	flag.StringVar(&opt.GF, "gf", "", "Pattern: ssrf,xss,sqli,lfi,rce,redirect")
	flag.BoolVar(&opt.Fuzz, "fuzz", false, "Replace param values with FUZZ")
	flag.BoolVar(&opt.JSON, "json", false, "JSONL output")
	flag.BoolVar(&opt.Silent, "silent", false, "Only print URLs")
	flag.BoolVar(&opt.Verbose, "v", false, "Show param count")
	flag.BoolVar(&opt.Tor, "tor", false, "Use Tor socks5 proxy")
	flag.StringVar(&opt.Proxy, "proxy", "", "Custom proxy URL")
	flag.Parse()

	// stdin support
	if fi, _ := os.Stdin.Stat(); (fi.Mode() & os.ModeCharDevice) == 0 {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" {
				opt.Targets = append(opt.Targets, line)
			}
		}
	}

	if domain != "" {
		opt.Targets = append(opt.Targets, domain)
	}

	if len(opt.Targets) == 0 {
		printBanner()
		flag.Usage()
		os.Exit(1)
	}

	engine := NewEngine(opt)

	engine.Providers = []Provider{
		&WaybackProvider{Client: engine.HttpClient},
		&CommonCrawlProvider{Client: engine.HttpClient},
		&URLScanProvider{Client: engine.HttpClient},
		&AlienVaultProvider{Client: engine.HttpClient},
		// &VirusTotalProvider{Client: engine.HttpClient}, // disabled — needs key
	}

	engine.Middlewares = []Middleware{&GFMiddleware{Pattern: opt.GF}}
	engine.Outputs = []Output{&CLIOutput{Silent: opt.Silent, Verbose: opt.Verbose}}

	var file *os.File
	if opt.OutputFile != "" {
		f, err := os.Create(opt.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot create output file: %v\n", err)
			os.Exit(1)
		}
		file = f
		engine.Outputs = append(engine.Outputs, &FileOutput{
			Writer: bufio.NewWriterSize(f, 128*1024),
			JSON:   opt.JSON,
		})
	}

	if !opt.Silent {
		printBanner()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := engine.Run(ctx)
	if err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "\n\033[31mError: %v\033[0m\n", err)
	}

	for _, o := range engine.Outputs {
		_ = o.Close()
	}
	if file != nil {
		_ = file.Close()
	}

	engine.PrintStats()
}

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	targetSuccesses = 20
	queryTimeout    = 2 * time.Second
	ednsUDPSize     = 1232
	domainListLimit = 1000
	httpTimeout     = 60 * time.Second
)

var (
	serverAddr = flag.String("server", "127.0.0.1", "target DNS server address")
	serverPort = flag.String("port", "53", "target DNS server port")
	logPath    = flag.String("log", "tester-trace.log", "path to deferred DNS trace log file (summary first, then query entries)")
	skipTLS    = flag.Bool("skip-tls", false, "skip DNS-over-TLS permutations without consuming domains")
)

// DomainPool provides thread-safe domain consumption for concurrent workers.
type DomainPool struct {
	mu      sync.Mutex
	domains []string
	index   int
}

// NewDomainPool wraps a domain slice in a pool with exclusive Pop semantics.
func NewDomainPool(domains []string) *DomainPool {
	copied := make([]string, len(domains))
	copy(copied, domains)
	return &DomainPool{domains: copied}
}

// Pop returns the next unused domain and false when the pool is exhausted.
func (p *DomainPool) Pop() (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.index >= len(p.domains) {
		return "", false
	}
	domain := p.domains[p.index]
	p.index++
	return domain, true
}

// Remaining reports how many domains are still available in the pool.
func (p *DomainPool) Remaining() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.domains) - p.index
}

// Consumed reports how many domains have been popped from the pool.
func (p *DomainPool) Consumed() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.index
}

// Total reports the initial number of domains in the pool.
func (p *DomainPool) Total() int {
	return len(p.domains)
}

// TestPermutation describes one DNS query scenario in the compliance matrix.
type TestPermutation struct {
	RecordType uint16
	Transport  string
	DNSSEC     bool
	EDNS       bool
}

// Label returns a compact permutation label for stdout summaries.
func (p TestPermutation) Label() string {
	typeName := dns.TypeToString[p.RecordType]
	if typeName == "" {
		typeName = fmt.Sprintf("TYPE%d", p.RecordType)
	}

	var flags []string
	if p.DNSSEC {
		flags = append(flags, "DNSSEC")
	}
	if p.EDNS {
		flags = append(flags, "EDNS")
	}
	if len(flags) == 0 {
		return fmt.Sprintf("%s/%s", typeName, p.Transport)
	}
	return fmt.Sprintf("%s/%s/%s", typeName, p.Transport, strings.Join(flags, "+"))
}

type trancoListMeta struct {
	ListID    string `json:"list_id"`
	Available bool   `json:"available"`
	Failed    bool   `json:"failed"`
	Download  string `json:"download"`
}

// logBuffer collects formatted log entries in memory for deferred file output.
type logBuffer struct {
	mu    sync.Mutex
	lines []string
}

func newLogBuffer() *logBuffer {
	return &logBuffer{}
}

func (b *logBuffer) Append(line string) {
	b.mu.Lock()
	b.lines = append(b.lines, line)
	b.mu.Unlock()
}

func (b *logBuffer) snapshot() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	copied := make([]string, len(b.lines))
	copy(copied, b.lines)
	return copied
}

var (
	stdoutMu sync.Mutex

	totalQueriesAttempted atomic.Uint64
	totalFailovers        atomic.Uint64
	successWithData       atomic.Uint64
	successEmpty          atomic.Uint64
)

func recordQueryOutcome(resp *dns.Msg, err error) (failover bool, exit bool) {
	totalQueriesAttempted.Add(1)

	if isQueryFailure(resp, err) {
		totalFailovers.Add(1)
		return true, false
	}

	if isQuerySuccess(resp) {
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			successWithData.Add(1)
		} else {
			successEmpty.Add(1)
		}
		return false, true
	}

	return false, false
}

func buildExecutionSummaryLines(permutationsRun int, pool *DomainPool) []string {
	consumed := pool.Consumed()
	total := pool.Total()

	return []string{
		"=========================================",
		"ARX-TESTER: EXECUTION SUMMARY",
		"=========================================",
		fmt.Sprintf("Total Permutations:      %d", permutationsRun),
		fmt.Sprintf("Total Domains Consumed:  %d (out of %d)", consumed, total),
		fmt.Sprintf("Total Queries Fired:     %d", totalQueriesAttempted.Load()),
		"-----------------------------------------",
		fmt.Sprintf("[✔] Success (With Data): %d", successWithData.Load()),
		fmt.Sprintf("[✔] Success (Empty/NX):  %d", successEmpty.Load()),
		fmt.Sprintf("[✖] Failovers Triggered: %d", totalFailovers.Load()),
		"=========================================",
	}
}

func printExecutionSummary(permutationsRun int, pool *DomainPool) {
	for _, line := range buildExecutionSummaryLines(permutationsRun, pool) {
		printStdout(line)
	}
}

func writeLogFile(path string, permutationsRun int, pool *DomainPool, buffer *logBuffer) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create trace log %q: %w", path, err)
	}
	defer file.Close()

	for _, line := range buildExecutionSummaryLines(permutationsRun, pool) {
		if _, err := file.WriteString(line + "\n"); err != nil {
			return fmt.Errorf("write summary to trace log: %w", err)
		}
	}
	if _, err := file.WriteString("\n"); err != nil {
		return fmt.Errorf("write trace log separator: %w", err)
	}
	for _, line := range buffer.snapshot() {
		if _, err := file.WriteString(line + "\n"); err != nil {
			return fmt.Errorf("write trace log entry: %w", err)
		}
	}
	return nil
}

func printStdout(line string) {
	stdoutMu.Lock()
	fmt.Println(line)
	stdoutMu.Unlock()
}

func buildPermutations() []TestPermutation {
	return []TestPermutation{
		{dns.TypeA, "udp", false, false},
		{dns.TypeA, "udp", false, true},
		{dns.TypeA, "udp", true, true},
		{dns.TypeA, "tcp", false, false},
		{dns.TypeA, "tcp", false, true},
		{dns.TypeA, "tcp", true, true},
		{dns.TypeA, "tls", false, true},
		{dns.TypeA, "tls", true, true},
		{dns.TypeAAAA, "udp", false, false},
		{dns.TypeAAAA, "udp", false, true},
		{dns.TypeAAAA, "udp", true, true},
		{dns.TypeAAAA, "tcp", false, true},
		{dns.TypeAAAA, "tcp", true, true},
		{dns.TypeAAAA, "tls", false, true},
		{dns.TypeAAAA, "tls", true, true},
		{dns.TypeMX, "udp", false, false},
		{dns.TypeMX, "udp", false, true},
		{dns.TypeMX, "udp", true, true},
		{dns.TypeMX, "tcp", false, true},
		{dns.TypeMX, "tcp", true, true},
		{dns.TypeMX, "tls", false, true},
		{dns.TypeSRV, "udp", false, true},
		{dns.TypeSRV, "udp", true, true},
		{dns.TypeSRV, "tcp", false, true},
		{dns.TypeSRV, "tcp", true, true},
		{dns.TypeSRV, "tls", true, true},
		{dns.TypeHTTPS, "udp", false, true},
		{dns.TypeHTTPS, "udp", true, true},
		{dns.TypeHTTPS, "tcp", false, true},
		{dns.TypeHTTPS, "tcp", true, true},
		{dns.TypeHTTPS, "tls", false, true},
		{dns.TypeHTTPS, "tls", true, true},
		{dns.TypeA, "udp", true, false},
		{dns.TypeAAAA, "tls", true, true},
		{dns.TypeMX, "udp", true, false},
	}
}

func fetchDomains(client *http.Client) ([]string, error) {
	domains, err := fetchTrancoDomains(client)
	if err == nil && len(domains) > 0 {
		return domains, nil
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "tranco fetch failed (%v), falling back to majestic\n", err)
	}
	return fetchMajesticDomains(client)
}

func fetchTrancoDomains(client *http.Client) ([]string, error) {
	meta, err := fetchTrancoListMeta(client)
	if err != nil {
		return nil, err
	}
	if !meta.Available || meta.Failed || meta.ListID == "" {
		return nil, errors.New("tranco latest list is not available")
	}

	downloadURL := fmt.Sprintf("https://tranco-list.eu/download/%s/%d", meta.ListID, domainListLimit)
	body, err := httpGetBody(client, downloadURL)
	if err != nil {
		return nil, fmt.Errorf("download tranco list: %w", err)
	}
	return parseDomainLines(body), nil
}

func fetchTrancoListMeta(client *http.Client) (*trancoListMeta, error) {
	body, err := httpGetBody(client, "https://tranco-list.eu/api/lists/date/latest")
	if err != nil {
		return nil, fmt.Errorf("query tranco metadata: %w", err)
	}

	var meta trancoListMeta
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("decode tranco metadata: %w", err)
	}
	return &meta, nil
}

func fetchMajesticDomains(client *http.Client) ([]string, error) {
	body, err := httpGetBody(client, "https://downloads.majestic.com/majestic_million.csv")
	if err != nil {
		return nil, fmt.Errorf("download majestic list: %w", err)
	}

	domains := make([]string, 0, domainListLimit)
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			continue
		}
		fields := strings.Split(scanner.Text(), ",")
		if len(fields) < 3 {
			continue
		}
		domain := normalizeDomain(fields[2])
		if domain == "" {
			continue
		}
		domains = append(domains, domain)
		if len(domains) >= domainListLimit {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan majestic list: %w", err)
	}
	if len(domains) == 0 {
		return nil, errors.New("majestic list contained no valid domains")
	}
	return domains, nil
}

func httpGetBody(client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "arx-tester/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s returned status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	return body, nil
}

func parseDomainLines(body []byte) []string {
	domains := make([]string, 0, domainListLimit)
	seen := make(map[string]struct{}, domainListLimit)

	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		domain := extractDomain(scanner.Text())
		if domain == "" {
			continue
		}
		if _, exists := seen[domain]; exists {
			continue
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
		if len(domains) >= domainListLimit {
			break
		}
	}
	return domains
}

func extractDomain(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}

	if strings.Contains(line, ",") {
		fields := strings.Split(line, ",")
		if len(fields) >= 2 {
			line = strings.TrimSpace(fields[1])
		}
	}

	return normalizeDomain(line)
}

func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" || !strings.Contains(domain, ".") {
		return ""
	}
	if len(domain) > 253 {
		return ""
	}
	if net.ParseIP(domain) != nil {
		return ""
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 {
			return ""
		}
	}
	return domain
}

// isQueryFailure reports whether a query should trigger domain failover.
// Failures are limited to transport errors, nil responses, SERVFAIL, and REFUSED.
func isQueryFailure(resp *dns.Msg, err error) bool {
	if err != nil {
		return true
	}
	if resp == nil {
		return true
	}
	return resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused
}

// isQuerySuccess reports whether a response counts toward the success target.
// NOERROR (including NODATA) and NXDOMAIN are valid resolver outcomes.
func isQuerySuccess(resp *dns.Msg) bool {
	if resp == nil {
		return false
	}
	return resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError
}

func failureReason(resp *dns.Msg, err error) string {
	if err != nil {
		return err.Error()
	}
	if resp == nil {
		return "nil response"
	}
	if name, ok := dns.RcodeToString[resp.Rcode]; ok {
		return name
	}
	return fmt.Sprintf("RCODE%d", resp.Rcode)
}

func formatOKLine(domain string, perm TestPermutation, resp *dns.Msg) string {
	rcode := dns.RcodeToString[resp.Rcode]
	if resp.Rcode == dns.RcodeSuccess {
		return fmt.Sprintf("[OK] %s (%s) - NOERROR (%d answers)", domain, perm.Label(), len(resp.Answer))
	}
	return fmt.Sprintf("[OK] %s (%s) - %s", domain, perm.Label(), rcode)
}

func summarizeAnswers(resp *dns.Msg) string {
	if len(resp.Answer) == 0 {
		return "[]"
	}

	parts := make([]string, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			parts = append(parts, v.A.String())
		case *dns.AAAA:
			parts = append(parts, v.AAAA.String())
		case *dns.MX:
			parts = append(parts, v.Mx)
		case *dns.SRV:
			parts = append(parts, v.Target)
		case *dns.HTTPS:
			parts = append(parts, v.Target)
		default:
			parts = append(parts, rr.String())
		}
		if len(parts) >= 5 {
			parts = append(parts, "...")
			break
		}
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func formatRTT(rtt time.Duration) string {
	return fmt.Sprintf("%dms", rtt.Round(time.Millisecond).Milliseconds())
}

func formatSuccessLog(domain string, perm TestPermutation, resp *dns.Msg, rtt time.Duration) string {
	rcode := dns.RcodeToString[resp.Rcode]
	rttLabel := formatRTT(rtt)
	if resp.Rcode == dns.RcodeNameError {
		return fmt.Sprintf("[OK] %s (%s) - %s RTT: %s", domain, perm.Label(), rcode, rttLabel)
	}
	return fmt.Sprintf("[OK] %s (%s) - %s - Answers: %s RTT: %s",
		domain, perm.Label(), rcode, summarizeAnswers(resp), rttLabel)
}

func formatFailureLog(domain string, perm TestPermutation, resp *dns.Msg, err error) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("[FAIL] %s (%s) - Reason: %s", domain, perm.Label(), failureReason(resp, err)))
	if resp != nil {
		parts = append(parts, resp.String())
	}
	return strings.Join(parts, "\n")
}

func appendQueryLog(buffer *logBuffer, domain string, perm TestPermutation, resp *dns.Msg, rtt time.Duration, err error) {
	if isQuerySuccess(resp) {
		buffer.Append(formatSuccessLog(domain, perm, resp, rtt))
		return
	}
	buffer.Append(formatFailureLog(domain, perm, resp, err))
}

func exchangeQuery(parent context.Context, server string, perm TestPermutation, domain string) (*dns.Msg, time.Duration, error) {
	ctx, cancel := context.WithTimeout(parent, queryTimeout)
	defer cancel()

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), perm.RecordType)
	msg.RecursionDesired = true

	if perm.EDNS || perm.DNSSEC {
		opt := &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeOPT,
			},
		}
		opt.SetUDPSize(ednsUDPSize)
		if perm.DNSSEC {
			opt.SetDo(true)
		}
		msg.Extra = []dns.RR{opt}
	}

	netTransport := perm.Transport
	if netTransport == "tls" {
		netTransport = "tcp-tls"
	}

	client := &dns.Client{
		Net:     netTransport,
		Timeout: queryTimeout,
	}
	if perm.Transport == "tls" {
		client.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}

	resp, rtt, err := client.ExchangeContext(ctx, msg, server)
	return resp, rtt, err
}

func tryRecordSuccess(count *int32) bool {
	for {
		current := atomic.LoadInt32(count)
		if current >= targetSuccesses {
			return false
		}
		if atomic.CompareAndSwapInt32(count, current, current+1) {
			return true
		}
	}
}

func runPermutation(parent context.Context, pool *DomainPool, server string, perm TestPermutation, buffer *logBuffer) error {
	var successCount int32
	workerCount := runtime.NumCPU() * 2
	if workerCount < 4 {
		workerCount = 4
	}
	if workerCount > targetSuccesses {
		workerCount = targetSuccesses
	}

	var wg sync.WaitGroup
	var exhausted atomic.Bool

	worker := func() {
		defer wg.Done()
		for atomic.LoadInt32(&successCount) < targetSuccesses {
			if exhausted.Load() {
				return
			}

			domain, ok := pool.Pop()
			if !ok {
				exhausted.Store(true)
				return
			}

			for atomic.LoadInt32(&successCount) < targetSuccesses {
				resp, rtt, err := exchangeQuery(parent, server, perm, domain)
				appendQueryLog(buffer, domain, perm, resp, rtt, err)

				failover, exit := recordQueryOutcome(resp, err)
				if failover {
					replacement, ok := pool.Pop()
					if !ok {
						exhausted.Store(true)
						return
					}
					printStdout(fmt.Sprintf("[FAILOVER] %s (%s) -> Reason: %s", domain, perm.Label(), failureReason(resp, err)))
					domain = replacement
					continue
				}

				if exit {
					if tryRecordSuccess(&successCount) {
						printStdout(formatOKLine(domain, perm, resp))
					}
					return
				}
				break
			}
		}
	}

	wg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go worker()
	}
	wg.Wait()

	if atomic.LoadInt32(&successCount) < targetSuccesses {
		return fmt.Errorf("permutation %s collected %d/%d successes (pool remaining: %d)",
			perm.Label(), successCount, targetSuccesses, pool.Remaining())
	}
	return nil
}

func main() {
	flag.Parse()

	server := net.JoinHostPort(*serverAddr, *serverPort)

	httpClient := &http.Client{Timeout: httpTimeout}

	fmt.Fprintf(os.Stderr, "fetching top %d domains...\n", domainListLimit)
	domains, err := fetchDomains(httpClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "domain fetch failed: %v\n", err)
		os.Exit(1)
	}
	if len(domains) < domainListLimit {
		fmt.Fprintf(os.Stderr, "warning: loaded %d domains (requested %d)\n", len(domains), domainListLimit)
	}

	pool := NewDomainPool(domains)
	perms := buildPermutations()

	buffer := newLogBuffer()

	fmt.Fprintf(os.Stderr, "loaded %d domains, running %d permutations x %d successes each against %s\n",
		len(domains), len(perms), targetSuccesses, server)

	ctx := context.Background()
	permutationsRun := 0
	for i, perm := range perms {
		fmt.Fprintf(os.Stderr, "permutation %d/%d: %s\n", i+1, len(perms), perm.Label())
		if *skipTLS && perm.Transport == "tls" {
			printStdout(fmt.Sprintf("[SKIP] Permutation %s ignored via -skip-tls flag", perm.Label()))
			continue
		}
		permutationsRun++
		if err := runPermutation(ctx, pool, server, perm, buffer); err != nil {
			fmt.Fprintf(os.Stderr, "permutation failed: %v\n", err)
			printExecutionSummary(permutationsRun, pool)
			if err := writeLogFile(*logPath, permutationsRun, pool, buffer); err != nil {
				fmt.Fprintf(os.Stderr, "trace log write failed: %v\n", err)
			}
			os.Exit(1)
		}
	}

	printStdout(fmt.Sprintf("[DONE] completed %d permutations with %d successes each; trace log: %s",
		permutationsRun, targetSuccesses, *logPath))
	printExecutionSummary(permutationsRun, pool)
	if err := writeLogFile(*logPath, permutationsRun, pool, buffer); err != nil {
		fmt.Fprintf(os.Stderr, "trace log write failed: %v\n", err)
		os.Exit(1)
	}
}

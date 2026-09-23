// retune-loadsim enrols simulated devices against a Retune server and has
// them check in and send inventory the way agents do, then reports how the
// server kept up. It is for sizing a server before a fleet arrives, against a
// server set up for the purpose: every simulated device stays enrolled.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"time"

	"retune/internal/agent/identity"
	"retune/internal/protocol"
)

const usage = `usage: retune-loadsim --server URL --token TOKEN (--ca FILE | --insecure) [flags]

Enrols --devices simulated devices with an enrollment token that allows that
many uses, then has each check in every --interval (with jitter) for
--duration, sending inventory whenever the server asks. Use a server set up
for the purpose: the devices stay enrolled afterwards.`

type options struct {
	server, token, caFile string
	insecure              bool
	devices, concurrency  int
	interval, duration    time.Duration
	software              int
}

func main() {
	var o options
	fs := flag.NewFlagSet("retune-loadsim", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, usage); fs.PrintDefaults() }
	fs.StringVar(&o.server, "server", "", "the server's URL, such as https://retune.example.com:8443")
	fs.StringVar(&o.token, "token", "", "an enrollment token good for --devices uses")
	fs.StringVar(&o.caFile, "ca", "", "the server's CA certificate (retune-server ca cert)")
	fs.BoolVar(&o.insecure, "insecure", false, "don't check the server's certificate (a throwaway test server only)")
	fs.IntVar(&o.devices, "devices", 100, "how many devices to simulate")
	fs.IntVar(&o.concurrency, "concurrency", 50, "how many enrolments run at once")
	fs.DurationVar(&o.interval, "interval", 5*time.Minute, "how often each device checks in (the server's default is 5m)")
	fs.DurationVar(&o.duration, "duration", 10*time.Minute, "how long to run once every device is enrolled")
	fs.IntVar(&o.software, "software", 150, "installed programs in each inventory, for a realistic size")
	_ = fs.Parse(os.Args[1:])
	if o.server == "" || o.token == "" || (o.caFile == "" && !o.insecure) {
		fs.Usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, o, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// stats collects latencies per operation.
type stats struct {
	mu     sync.Mutex
	ok     map[string][]time.Duration
	failed map[string]int
	errs   map[string]string
}

func newStats() *stats {
	return &stats{ok: map[string][]time.Duration{}, failed: map[string]int{}, errs: map[string]string{}}
}

func (s *stats) record(op string, d time.Duration, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.failed[op]++
		s.errs[op] = err.Error()
		return
	}
	s.ok[op] = append(s.ok[op], d)
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(p * float64(len(sorted)-1))
	return sorted[i]
}

func (s *stats) report(w io.Writer, elapsed time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ops := []string{"enroll", "checkin", "inventory"}
	fmt.Fprintf(w, "%-10s %8s %8s %9s %9s %9s %9s\n", "operation", "ok", "failed", "per sec", "p50", "p95", "p99")
	for _, op := range ops {
		lat := append([]time.Duration(nil), s.ok[op]...)
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		rate := float64(len(lat)) / elapsed.Seconds()
		if op == "enroll" {
			rate = 0 // enrolment runs before the timed phase
		}
		fmt.Fprintf(w, "%-10s %8d %8d %9.1f %9s %9s %9s\n", op, len(lat), s.failed[op], rate,
			percentile(lat, 0.50).Round(time.Millisecond), percentile(lat, 0.95).Round(time.Millisecond),
			percentile(lat, 0.99).Round(time.Millisecond))
	}
	for op, e := range s.errs {
		fmt.Fprintf(w, "last %s error: %s\n", op, e)
	}
}

// device is one simulated agent.
type device struct {
	id       string
	hostname string
	client   *http.Client
	inv      []byte
	// invHash is what the server acknowledged for the last upload, sent
	// with each check-in as an agent does, so inventory is asked for only
	// when the server wants it.
	invHash string
}

func run(ctx context.Context, o options, out io.Writer) error {
	roots, err := trust(o)
	if err != nil {
		return err
	}
	base := strings.TrimRight(o.server, "/")
	st := newStats()

	fmt.Fprintf(out, "enrolling %d devices, %d at a time...\n", o.devices, o.concurrency)
	start := time.Now()
	devices := make([]*device, o.devices)
	sem := make(chan struct{}, o.concurrency)
	var wg sync.WaitGroup
	for i := range devices {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			t := time.Now()
			d, err := enroll(ctx, base, o, roots, i)
			st.record("enroll", time.Since(t), err)
			devices[i] = d
		}(i)
	}
	wg.Wait()
	enrolled := 0
	for _, d := range devices {
		if d != nil {
			enrolled++
		}
	}
	fmt.Fprintf(out, "enrolled %d in %s\n", enrolled, time.Since(start).Round(time.Second))
	if enrolled == 0 {
		st.report(out, time.Second)
		return errors.New("no device enrolled")
	}

	fmt.Fprintf(out, "checking in every %s for %s (about %.1f check-ins a second)...\n",
		o.interval, o.duration, float64(enrolled)/o.interval.Seconds())
	runCtx, cancel := context.WithTimeout(ctx, o.duration)
	defer cancel()
	begun := time.Now()
	for _, d := range devices {
		if d == nil {
			continue
		}
		wg.Add(1)
		go func(d *device) {
			defer wg.Done()
			// Spread the first check-ins over one interval, as a fleet's are.
			first := time.Duration(rand.Int64N(int64(o.interval)))
			timer := time.NewTimer(first)
			defer timer.Stop()
			for {
				select {
				case <-runCtx.Done():
					return
				case <-timer.C:
				}
				checkin(runCtx, base, d, st)
				// ±10% jitter, as the agent adds.
				next := o.interval + time.Duration((rand.Float64()*0.2-0.1)*float64(o.interval))
				timer.Reset(next)
			}
		}(d)
	}
	wg.Wait()
	elapsed := time.Since(begun)
	fmt.Fprintf(out, "\nafter %s:\n", elapsed.Round(time.Second))
	st.report(out, elapsed)
	return nil
}

func trust(o options) (*x509.CertPool, error) {
	if o.insecure {
		return nil, nil
	}
	pemBytes, err := os.ReadFile(o.caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("%s has no PEM certificate", o.caFile)
	}
	return pool, nil
}

func tlsConfig(roots *x509.CertPool, cert *tls.Certificate) *tls.Config {
	cfg := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, InsecureSkipVerify: roots == nil} //nolint:gosec // --insecure only
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return cfg
}

func enroll(ctx context.Context, base string, o options, roots *x509.CertPool, n int) (*device, error) {
	hostname := fmt.Sprintf("LOADSIM-%05d-%04x", n, rand.IntN(0xffff))
	key, csr, err := identity.NewKeyAndCSR(hostname)
	if err != nil {
		return nil, err
	}
	anon := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig(roots, nil)}}
	var resp protocol.EnrollResponse
	err = post(ctx, anon, http.MethodPost, base+"/api/agent/v1/enroll", protocol.EnrollRequest{
		Token: o.token, CSRPEM: csr,
		Device: protocol.DeviceFacts{
			Hostname: hostname, Serial: fmt.Sprintf("SIM%08d", n), SMBIOSUUID: fmt.Sprintf("00000000-0000-4000-8000-%012d", n),
			OSVersion: "Microsoft Windows 11 Pro 10.0.26100",
		},
	}, &resp)
	if err != nil {
		return nil, err
	}
	cert, err := tlsPair(resp.CertPEM, key)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig(roots, &cert), MaxIdleConnsPerHost: 1}
	inv, err := json.Marshal(inventory(hostname, n, o.software))
	if err != nil {
		return nil, err
	}
	return &device{
		id: resp.DeviceID, hostname: hostname, inv: inv,
		client: &http.Client{Timeout: 60 * time.Second, Transport: transport},
	}, nil
}

func tlsPair(certPEM string, key *ecdsa.PrivateKey) (tls.Certificate, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return tls.X509KeyPair([]byte(certPEM), keyPEM)
}

func checkin(ctx context.Context, base string, d *device, st *stats) {
	t := time.Now()
	var resp protocol.CheckinResponse
	err := post(ctx, d.client, http.MethodPost, base+"/api/agent/v1/checkin", protocol.CheckinRequest{
		AgentVersion: "1.0.0", UptimeSeconds: 3600, IPAddresses: []string{"10.0.0.1"}, InventoryHash: d.invHash,
	}, &resp)
	if ctx.Err() != nil {
		return // the run ended mid-request; not the server's fault
	}
	st.record("checkin", time.Since(t), err)
	if err == nil && resp.InventoryDue {
		t = time.Now()
		var ack protocol.InventoryResponse
		err = post(ctx, d.client, http.MethodPut, base+"/api/agent/v1/inventory", json.RawMessage(d.inv), &ack)
		if ctx.Err() == nil {
			st.record("inventory", time.Since(t), err)
		}
		if err == nil {
			d.invHash = ack.Hash
		}
	}
}

func post(ctx context.Context, c *http.Client, method, url string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %d %s", method, url, res.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// inventory is a plausible Windows machine's inventory, with software
// programs, so uploads are about the size real ones are.
func inventory(hostname string, n, software int) protocol.Inventory {
	now := time.Now().UTC()
	inv := protocol.Inventory{
		CollectedAt: now, Hostname: hostname,
		OS: protocol.OSInfo{Name: "Microsoft Windows 11 Pro", Version: "10.0.26100", Build: "26100"},
		Hardware: protocol.Hardware{
			Manufacturer: "Contoso", Model: "Book 9", Serial: fmt.Sprintf("SIM%08d", n),
			SMBIOSUUID: fmt.Sprintf("00000000-0000-4000-8000-%012d", n), CPU: "Intel(R) Core(TM) Ultra 7", CPULogical: 16,
			RAMBytes: 32 << 30,
		},
		Disks:       []protocol.Disk{{Name: "C:", SizeBytes: 512 << 30, FreeBytes: 200 << 30}},
		LocalAdmins: []string{"Administrator"},
	}
	for i := 0; i < software; i++ {
		inv.Software = append(inv.Software, protocol.Software{
			Name: fmt.Sprintf("Simulated Application %03d", i), Version: fmt.Sprintf("%d.%d.%d", i%9+1, i%7, i),
			Publisher: "Contoso Ltd",
		})
	}
	return inv
}

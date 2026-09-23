package alerts

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
)

// errForbiddenTarget is a webhook aimed at an address the server will not
// post to.
var errForbiddenTarget = errors.New("that address is not allowed for a webhook")

// webhookClient is the client alert webhooks go out through. It refuses to
// connect to loopback or link-local addresses - the server's own local
// services, and the cloud metadata endpoint at 169.254.169.254 - checking the
// address actually dialled, so a hostname that resolves somewhere else on the
// second lookup gets no further than one that did on the first. It does not
// follow redirects, so a receiver cannot bounce the request somewhere the URL
// did not name.
//
// Private ranges are allowed: a self-hosted Retune posting to a SIEM or chat
// server on the same network is ordinary, and the admins who configure
// webhooks can already run code on every managed machine.
func webhookClient() *http.Client {
	dialer := &net.Dialer{Timeout: webhookTimeout, Control: refuseLocalTargets}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = dialer.DialContext
	return &http.Client{
		Transport: transport,
		Timeout:   webhookTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func refuseLocalTargets(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("%w: %s", errForbiddenTarget, ip)
	}
	return nil
}

// deliveryError says what went wrong posting to target without repeating the
// URL itself. Go's client puts the whole URL in its errors, and for Slack,
// Teams and many other receivers the path is the credential: a delivery log
// that read-only accounts can see must not hand it to them.
func deliveryError(target string, err error) error {
	host := "the webhook"
	if u, perr := url.Parse(target); perr == nil && u.Host != "" {
		host = u.Host
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return fmt.Errorf("posting to %s: %v", host, err)
}

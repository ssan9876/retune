package alerts

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestWebhooksRefuseLoopbackAndLinkLocal(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:443", "[::1]:443", "169.254.169.254:80", "[fe80::1]:443", "0.0.0.0:443", "[::ffff:127.0.0.1]:443"} {
		if err := refuseLocalTargets("tcp", addr, nil); !errors.Is(err, errForbiddenTarget) {
			t.Errorf("%s should be refused, got %v", addr, err)
		}
	}
	// A receiver on the same private network is an ordinary self-hosted setup.
	for _, addr := range []string{"10.0.0.5:443", "192.168.1.20:8443", "203.0.113.7:443", "[2001:db8::1]:443"} {
		if err := refuseLocalTargets("tcp", addr, nil); err != nil {
			t.Errorf("%s should be allowed, got %v", addr, err)
		}
	}
}

func TestWebhooksDoNotFollowRedirects(t *testing.T) {
	if err := webhookClient().CheckRedirect(&http.Request{}, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("a redirect must not be followed, got %v", err)
	}
}

// Slack, Teams and the like put the credential in the URL's path, and Go's
// client repeats the whole URL in its errors. What is stored must not.
func TestDeliveryErrorsDoNotRepeatTheURL(t *testing.T) {
	target := "https://hooks.slack.com/services/T000/B000/SECRETSECRET"
	err := deliveryError(target, &url.Error{Op: "Post", URL: target, Err: errors.New("connection refused")})
	if strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "hooks.slack.com") {
		t.Fatalf("error = %q", err)
	}
}

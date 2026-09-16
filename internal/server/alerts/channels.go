package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"retune/internal/server/store"
)

// ErrBadChannel is returned for a channel definition the caller can fix.
var ErrBadChannel = errors.New("invalid notification channel")

// maxRecipients is a ceiling on one channel's address list. A distribution
// list is the right way to tell fifty people; fifty addresses on a channel is
// a way to get a deployment's mail marked as spam.
const maxRecipients = 20

// webhookTimeout bounds one POST. Delivery happens under the sweeper's
// advisory lock, so a receiver that accepts a connection and then says
// nothing must not hold the whole alerting job.
const webhookTimeout = 10 * time.Second

// ChannelConfig is every channel kind's configuration in one value; each kind
// reads only its own fields.
type ChannelConfig struct {
	// To is an email channel's recipients.
	To []string `json:"to,omitempty"`
	// URL is a webhook channel's endpoint.
	URL string `json:"url,omitempty"`
}

// ParseChannelConfig reads and validates one channel's configuration.
func ParseChannelConfig(kind string, raw []byte) (ChannelConfig, error) {
	var c ChannelConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if len(raw) > 0 {
		if err := dec.Decode(&c); err != nil {
			return ChannelConfig{}, fmt.Errorf("%w: %v", ErrBadChannel, err)
		}
	}
	switch kind {
	case store.ChannelEmail:
		if c.URL != "" {
			return ChannelConfig{}, fmt.Errorf("%w: url does not apply to an email channel", ErrBadChannel)
		}
		if len(c.To) == 0 {
			return ChannelConfig{}, fmt.Errorf("%w: an email channel needs at least one recipient", ErrBadChannel)
		}
		if len(c.To) > maxRecipients {
			return ChannelConfig{}, fmt.Errorf("%w: at most %d recipients", ErrBadChannel, maxRecipients)
		}
		for i, addr := range c.To {
			parsed, err := mail.ParseAddress(strings.TrimSpace(addr))
			if err != nil {
				return ChannelConfig{}, fmt.Errorf("%w: %q is not an email address", ErrBadChannel, addr)
			}
			c.To[i] = parsed.Address
		}
	case store.ChannelWebhook:
		if len(c.To) > 0 {
			return ChannelConfig{}, fmt.Errorf("%w: to does not apply to a webhook channel", ErrBadChannel)
		}
		u, err := url.Parse(strings.TrimSpace(c.URL))
		// https only: the body names devices and what is wrong with them, and
		// the signature proves who sent it but hides nothing.
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return ChannelConfig{}, fmt.Errorf("%w: url must be an https URL", ErrBadChannel)
		}
		c.URL = u.String()
	default:
		return ChannelConfig{}, fmt.Errorf("%w: unsupported kind %q", ErrBadChannel, kind)
	}
	return c, nil
}

// webhookPayload is what a receiver gets. It is deliberately the same shape
// for every rule kind, so one handler on the other end can route on `kind`
// rather than parse prose.
type webhookPayload struct {
	Rule        string           `json:"rule"`
	Kind        string           `json:"kind"`
	Description string           `json:"description"`
	At          string           `json:"at"`
	Firing      []payloadSubject `json:"firing"`
	Resolved    []payloadSubject `json:"resolved"`
}

type payloadSubject struct {
	Key     string `json:"subject_key"`
	Subject string `json:"subject"`
}

func subjects(in []store.AlertSubject) []payloadSubject {
	out := make([]payloadSubject, 0, len(in))
	for _, s := range in {
		out = append(out, payloadSubject{Key: s.Key, Subject: s.Subject})
	}
	return out
}

// postWebhook delivers one message and reports what the receiver said. Any 2xx
// is success; everything else carries its status into the delivery record, so
// a misconfigured endpoint shows up in the console as a 404 rather than as
// silence.
func postWebhook(ctx context.Context, client *http.Client, cfg ChannelConfig, secret []byte, m Message) error {
	body, err := json.Marshal(webhookPayload{
		Rule:        m.RuleName,
		Kind:        m.Kind,
		Description: m.Description,
		At:          m.At.UTC().Format(time.RFC3339),
		Firing:      subjects(m.Firing),
		Resolved:    subjects(m.Resolved),
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, webhookTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "retune-server")
	if len(secret) > 0 {
		// Over the exact bytes sent, so a receiver verifies what it read
		// rather than what it re-encoded.
		mac := hmac.New(sha256.New, secret)
		mac.Write(body)
		req.Header.Set("X-Retune-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	// Read and discard a little of the body so the connection can be reused,
	// and so a chatty error page does not end up in the delivery record.
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("webhook returned %s", res.Status)
	}
	return nil
}

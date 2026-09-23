package alerts

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/secrets"
	"retune/internal/server/store"
)

// maxNamed is how many subjects a message lists by name before it gives up
// and counts the rest. A fleet-wide problem is one message either way; what
// this bounds is how long that message is.
const maxNamed = 20

// deliveryRetention is how long the delivery record is kept.
const deliveryRetention = 30 * 24 * time.Hour

// Message is what one rule has to say on one tick.
type Message struct {
	RuleName    string
	Kind        string
	Description string
	At          time.Time
	Firing      []store.AlertSubject
	Resolved    []store.AlertSubject
}

// Empty reports whether there is nothing worth sending.
func (m Message) Empty() bool { return len(m.Firing) == 0 && len(m.Resolved) == 0 }

// Subject is the email subject line, and the one-line summary the console
// shows beside a delivery.
func (m Message) Subject() string {
	var parts []string
	if n := len(m.Firing); n > 0 {
		parts = append(parts, fmt.Sprintf("%d new", n))
	}
	if n := len(m.Resolved); n > 0 {
		parts = append(parts, fmt.Sprintf("%d resolved", n))
	}
	return fmt.Sprintf("Retune: %s - %s", m.RuleName, strings.Join(parts, ", "))
}

// Body is the plain-text message. Every alert reads the same way whatever
// rule produced it: what the rule watches for, what has started, what has
// stopped.
func (m Message) Body() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Rule: %s\n", m.RuleName)
	fmt.Fprintf(&b, "Fires when: %s\n", m.Description)
	fmt.Fprintf(&b, "At: %s\n", m.At.UTC().Format(time.RFC1123))
	writeList(&b, "Now firing", m.Firing)
	writeList(&b, "Resolved", m.Resolved)
	return b.String()
}

func writeList(b *strings.Builder, heading string, list []store.AlertSubject) {
	if len(list) == 0 {
		return
	}
	fmt.Fprintf(b, "\n%s (%d):\n", heading, len(list))
	for i, s := range list {
		if i == maxNamed {
			fmt.Fprintf(b, "  ... and %d more.\n", len(list)-maxNamed)
			return
		}
		fmt.Fprintf(b, "  - %s\n", s.Subject)
	}
}

// Service evaluates alert rules and delivers what changed.
type Service struct {
	Store *store.Store
	// Key seals webhook secrets, the same key that protects escrowed
	// BitLocker recovery keys.
	Key    *secrets.Key
	Now    func() time.Time
	Log    *slog.Logger
	SMTP   SMTP
	Mailer Mailer
	// HTTP posts webhooks. Nil means webhookClient, which refuses loopback
	// and link-local targets and does not follow redirects; tests supply one
	// that trusts their own receiver.
	HTTP *http.Client

	defaultClient sync.Once
	fallback      *http.Client
}

func (s *Service) client() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	s.defaultClient.Do(func() { s.fallback = webhookClient() })
	return s.fallback
}

// AttachmentMailer is the mailer scheduled reports send through: the relay
// alerts use.
func (s *Service) AttachmentMailer() AttachmentMailer {
	if m, ok := s.Mailer.(AttachmentMailer); ok {
		return m
	}
	return SMTPMailer{Config: s.SMTP}
}

// SMTPConfigured reports whether email can be sent at all.
func (s *Service) SMTPConfigured() bool { return s.Mailer != nil || s.SMTP.Configured() }

func (s *Service) mailer() Mailer {
	if s.Mailer != nil {
		return s.Mailer
	}
	return SMTPMailer{Config: s.SMTP}
}

// SealSecret encrypts a webhook's shared secret for storage. The channel's id
// is authenticated along with it, so a ciphertext copied onto a different
// channel row will not decrypt.
func (s *Service) SealSecret(channelID uuid.UUID, secret string) (ciphertext, nonce []byte, err error) {
	if secret == "" {
		return nil, nil, nil
	}
	return s.Key.Seal([]byte(secret), SecretContext(channelID))
}

// SecretContext is what a channel's sealed secret is bound to.
func SecretContext(channelID uuid.UUID) []byte { return []byte(channelID.String()) }

func (s *Service) openSecret(ch store.NotificationChannel) ([]byte, error) {
	if len(ch.SecretCiphertext) == 0 {
		return nil, nil
	}
	return s.Key.Open(ch.SecretCiphertext, ch.SecretNonce, SecretContext(ch.ID))
}

// Deliver sends one message through one channel.
func (s *Service) Deliver(ctx context.Context, ch store.NotificationChannel, m Message) error {
	cfg, err := ParseChannelConfig(ch.Kind, ch.Config)
	if err != nil {
		return err
	}
	switch ch.Kind {
	case store.ChannelEmail:
		return s.mailer().Send(ctx, cfg.To, m.Subject(), m.Body())
	case store.ChannelWebhook:
		secret, err := s.openSecret(ch)
		if err != nil {
			return err
		}
		return postWebhook(ctx, s.client(), cfg, secret, m)
	}
	return fmt.Errorf("%w: unsupported kind %q", ErrBadChannel, ch.Kind)
}

// Test sends a fixed message through a channel, so an administrator finds out
// that the relay is wrong while they are still looking at the form.
func (s *Service) Test(ctx context.Context, ch store.NotificationChannel) error {
	now := s.Now()
	return s.Deliver(ctx, ch, Message{
		RuleName:    "Test",
		Kind:        "test",
		Description: "somebody asked Retune to prove this channel works",
		At:          now,
		Firing: []store.AlertSubject{{
			Key:     "test",
			Subject: "This is a test. Nothing is wrong.",
		}},
	})
}

// EvaluateAll runs every enabled rule and delivers what changed. It is the
// sweeper's job body, so it runs under an advisory lock and only one replica
// sends per tick. It returns the number of subjects that started or stopped
// firing, which is what the sweeper logs.
//
// A rule that fails is logged and skipped rather than failing the tick: one
// bad rule must not stop the others from being evaluated, the same way one
// device's failure does not stop a compliance pass.
func (s *Service) EvaluateAll(ctx context.Context, q *store.Queries, now time.Time) (int64, error) {
	rules, err := q.ListAlertRules(ctx, true)
	if err != nil {
		return 0, err
	}
	var changed int64
	for _, rule := range rules {
		n, err := s.evaluateRule(ctx, q, rule, now)
		if err != nil {
			s.Log.Warn("alert rule failed", "rule", rule.Name, "kind", rule.Kind, "error", err)
			continue
		}
		changed += n
	}
	if _, err := q.DeleteOldAlertDeliveries(ctx, now.Add(-deliveryRetention)); err != nil {
		s.Log.Warn("pruning alert deliveries failed", "error", err)
	}
	return changed, nil
}

func (s *Service) evaluateRule(ctx context.Context, q *store.Queries, rule store.AlertRule, now time.Time) (int64, error) {
	params, err := ParseParams(rule.Kind, rule.Params)
	if err != nil {
		return 0, err
	}
	found, err := firing(ctx, q, rule.Kind, params, now)
	if err != nil {
		return 0, err
	}
	known, err := q.ListAlertState(ctx, rule.ID)
	if err != nil {
		return 0, err
	}

	var newly, resolved []store.AlertSubject
	stillFiring := make(map[string]bool, len(found))
	for _, subject := range found {
		stillFiring[subject.Key] = true
		prior, seen := known[subject.Key]
		if err := q.InsertAlertState(ctx, rule.ID, subject, now); err != nil {
			return 0, err
		}
		// Not yet notified counts as new, which is what turns a failed
		// delivery into a retry on the next tick instead of a lost alert.
		if !seen || prior.NotifiedAt == nil {
			newly = append(newly, subject)
		}
	}
	var goneKeys []string
	for key, prior := range known {
		if stillFiring[key] {
			continue
		}
		goneKeys = append(goneKeys, key)
		// A subject that never got as far as being announced needs no
		// all-clear: nobody was told it was wrong.
		if prior.NotifiedAt != nil {
			resolved = append(resolved, store.AlertSubject{Key: key, Subject: prior.Subject})
		}
	}
	if err := q.DeleteAlertState(ctx, rule.ID, goneKeys); err != nil {
		return 0, err
	}

	msg := Message{
		RuleName: rule.Name, Kind: rule.Kind, Description: Describe(rule.Kind, params),
		At: now, Firing: newly, Resolved: resolved,
	}
	if msg.Empty() {
		return 0, nil
	}
	ch, err := q.GetNotificationChannel(ctx, store.DefaultTenantID, rule.ChannelID)
	if err != nil {
		return 0, err
	}
	if !ch.Enabled {
		// State is still kept up to date above, so re-enabling a channel
		// starts from what is wrong now rather than replaying a backlog.
		return int64(len(newly) + len(resolved)), nil
	}

	sendErr := s.Deliver(ctx, ch, msg)
	record := store.AlertDelivery{
		RuleID: rule.ID, At: now, OK: sendErr == nil,
		Firing: len(newly), Resolved: len(resolved),
	}
	if sendErr != nil {
		record.Detail = sendErr.Error()
	}
	if err := q.InsertAlertDelivery(ctx, record, ch.ID); err != nil {
		return 0, err
	}
	if sendErr != nil {
		return 0, sendErr
	}
	keys := make([]string, 0, len(newly))
	for _, subject := range newly {
		keys = append(keys, subject.Key)
	}
	if err := q.MarkAlertsNotified(ctx, rule.ID, keys, now); err != nil {
		return 0, err
	}
	return int64(len(newly) + len(resolved)), nil
}

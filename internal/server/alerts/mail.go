package alerts

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// smtpTimeout bounds dialling and the conversation that follows.
const smtpTimeout = 20 * time.Second

// ErrNoSMTP is returned when an email channel is used on a deployment with no
// relay configured. It is reported when the channel is created, not when the
// first alert silently fails to arrive.
var ErrNoSMTP = errors.New("no SMTP server is configured (set SMTP_HOST and SMTP_FROM)")

// SMTP is the relay this deployment sends through. It is process
// configuration rather than a column on a channel: one relay per deployment,
// and a password stored in a row the console can read back is a password
// nobody should have stored.
type SMTP struct {
	Host     string
	Port     int
	From     string
	Username string
	Password string
	// StartTLS upgrades the connection before authenticating. On by default;
	// off is for a relay on localhost that does not offer it.
	StartTLS bool
}

// Configured reports whether email can be sent at all.
func (s SMTP) Configured() bool { return s.Host != "" && s.From != "" }

// Mailer sends one message. It is an interface so tests exercise the message
// a rule produces without opening a socket to a mail relay.
type Mailer interface {
	Send(ctx context.Context, to []string, subject, body string) error
}

// SMTPMailer is the real sender.
type SMTPMailer struct{ Config SMTP }

func (m SMTPMailer) Send(ctx context.Context, to []string, subject, body string) error {
	if !m.Config.Configured() {
		return ErrNoSMTP
	}
	addr := net.JoinHostPort(m.Config.Host, fmt.Sprint(m.Config.Port))
	// net/smtp has no context, so the deadline is put on the connection: a
	// relay that accepts TCP and then stops talking must not hold the
	// sweeper's lock until something else notices.
	dialer := net.Dialer{Timeout: smtpTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(smtpTimeout))
	}
	client, err := smtp.NewClient(conn, m.Config.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer client.Close()

	if m.Config.StartTLS {
		if err := client.StartTLS(nil); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}
	if m.Config.Username != "" {
		// PlainAuth refuses to send credentials over an unencrypted
		// connection unless the server is localhost, which is exactly the
		// check that should be made here rather than worked around.
		auth := smtp.PlainAuth("", m.Config.Username, m.Config.Password, m.Config.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("authenticate: %w", err)
		}
	}
	if err := client.Mail(m.Config.From); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("recipient %s: %w", rcpt, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(message(m.Config.From, to, subject, body))); err != nil {
		w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// message assembles the RFC 5322 bytes. Header values are stripped of CR and
// LF first: a hostname is device-reported text, and a newline in a Subject
// line is how a header becomes two headers.
func message(from string, to []string, subject, body string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", headerSafe(from))
	fmt.Fprintf(&b, "To: %s\r\n", headerSafe(strings.Join(to, ", ")))
	fmt.Fprintf(&b, "Subject: %s\r\n", headerSafe(subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	// Bare newlines in the body become CRLF, and a line that is only a dot
	// would otherwise end the DATA command early.
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		if line == "." {
			line = ".."
		}
		b.WriteString(line)
		b.WriteString("\r\n")
	}
	return b.String()
}

func headerSafe(v string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(v)
}

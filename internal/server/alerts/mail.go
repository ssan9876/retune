package alerts

import (
	"context"
	"encoding/base64"
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

// Attachment is a file sent with a message.
type Attachment struct {
	Name        string
	ContentType string
	Data        []byte
}

// AttachmentMailer sends a message with files attached.
type AttachmentMailer interface {
	SendWithAttachments(ctx context.Context, to []string, subject, body string, files []Attachment) error
}

// SMTPMailer is the real sender.
type SMTPMailer struct{ Config SMTP }

func (m SMTPMailer) Send(ctx context.Context, to []string, subject, body string) error {
	return m.deliver(ctx, to, message(m.Config.From, to, subject, body, nil))
}

// SendWithAttachments sends a message with files attached.
func (m SMTPMailer) SendWithAttachments(ctx context.Context, to []string, subject, body string, files []Attachment) error {
	return m.deliver(ctx, to, message(m.Config.From, to, subject, body, files))
}

func (m SMTPMailer) deliver(ctx context.Context, to []string, raw string) error {
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
	if _, err := w.Write([]byte(raw)); err != nil {
		w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// message assembles the RFC 5322 bytes: plain text, or with files attached
// multipart/mixed. Header values are stripped of CR and LF first: a hostname
// is device-reported text, and a newline in a Subject line is how a header
// becomes two headers.
func message(from string, to []string, subject, body string, files []Attachment) string {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", headerSafe(from))
	fmt.Fprintf(&b, "To: %s\r\n", headerSafe(strings.Join(to, ", ")))
	fmt.Fprintf(&b, "Subject: %s\r\n", headerSafe(subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	if len(files) == 0 {
		b.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
		writeText(&b, body)
		return b.String()
	}
	boundary := "retune-" + strings.ReplaceAll(time.Now().UTC().Format("20060102T150405.000000000"), ".", "")
	fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=%q\r\n\r\n", boundary)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n", boundary)
	writeText(&b, body)
	for _, f := range files {
		name := strings.NewReplacer(`"`, "", "\\", "", "\r", "", "\n", "").Replace(f.Name)
		fmt.Fprintf(&b, "--%s\r\n", boundary)
		fmt.Fprintf(&b, "Content-Type: %s; name=%q\r\n", headerSafe(f.ContentType), name)
		fmt.Fprintf(&b, "Content-Disposition: attachment; filename=%q\r\n", name)
		b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
		encoded := base64.StdEncoding.EncodeToString(f.Data)
		for len(encoded) > 76 {
			b.WriteString(encoded[:76])
			b.WriteString("\r\n")
			encoded = encoded[76:]
		}
		b.WriteString(encoded)
		b.WriteString("\r\n")
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.String()
}

// writeText writes a plain-text body with CRLF line endings. A line that is
// only a dot would otherwise end the DATA command early.
func writeText(b *strings.Builder, body string) {
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		if line == "." {
			line = ".."
		}
		b.WriteString(line)
		b.WriteString("\r\n")
	}
}

func headerSafe(v string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(v)
}

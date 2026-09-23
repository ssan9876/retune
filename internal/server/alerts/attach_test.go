package alerts

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
)

// A message with files attached parses back, as a mail reader would, into
// the text and the files.
func TestMessageWithAttachments(t *testing.T) {
	data := bytes.Repeat([]byte("hostname,state\nPC-1,compliant\n"), 20)
	raw := message("retune@example.com", []string{"ops@example.com"}, "Report", "See attached.",
		[]Attachment{{Name: `devices "all".csv`, ContentType: "text/csv", Data: data}})

	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/mixed" {
		t.Fatalf("content type %q: %v", mediaType, err)
	}
	r := multipart.NewReader(msg.Body, params["boundary"])
	text, err := r.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if body, _ := io.ReadAll(text); strings.TrimSpace(string(body)) != "See attached." {
		t.Fatalf("text = %q", body)
	}
	file, err := r.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if file.FileName() != "devices all.csv" || file.Header.Get("Content-Transfer-Encoding") != "base64" {
		t.Fatalf("file %q, %v", file.FileName(), file.Header)
	}
	got, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeBase64Lines(t, got)
	if !bytes.Equal(decoded, data) {
		t.Fatal("the attachment doesn't round-trip")
	}
	for _, line := range strings.Split(string(got), "\r\n") {
		if len(line) > 76 {
			t.Fatalf("a base64 line of %d characters", len(line))
		}
	}
	if _, err := r.NextPart(); err != io.EOF {
		t.Fatalf("after the file: %v", err)
	}
}

func decodeBase64Lines(t *testing.T, b []byte) []byte {
	t.Helper()
	out, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.TrimSpace(string(b)), "\r\n", ""))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

package executor

import (
	"context"
	"errors"
	"strings"
	"testing"

	"retune/internal/protocol"
)

type fakePasswords struct {
	builtin string
	set     map[string]string
	err     error
}

func (f *fakePasswords) BuiltinAdmin(context.Context) (string, error) { return f.builtin, nil }

func (f *fakePasswords) SetPassword(_ context.Context, account, password string) error {
	if f.err != nil {
		return f.err
	}
	f.set[account] = password
	return nil
}

type fakeEscrower struct {
	got []protocol.AdminPasswordEscrowRequest
	err error
}

func (f *fakeEscrower) EscrowAdminPassword(_ context.Context, req protocol.AdminPasswordEscrowRequest) error {
	f.got = append(f.got, req)
	return f.err
}

func TestRotateEscrowsThenSets(t *testing.T) {
	pw := &fakePasswords{builtin: "LocalBoss", set: map[string]string{}}
	esc := &fakeEscrower{}
	e := &Executor{Passwords: pw, Escrower: esc}

	res := e.Execute(context.Background(), cmd(t, protocol.CommandRotateAdminPassword,
		protocol.RotateAdminPasswordPayload{Length: 30}))
	if res.Status != protocol.ResultSucceeded {
		t.Fatalf("rotate = %+v", res)
	}
	// The built-in Administrator, whatever it's called, when no account is named.
	if len(esc.got) != 1 || esc.got[0].Account != "LocalBoss" || esc.got[0].CommandID != "c1" {
		t.Fatalf("escrowed %+v", esc.got)
	}
	if pw.set["LocalBoss"] != esc.got[0].Password || len([]rune(pw.set["LocalBoss"])) != 30 {
		t.Fatalf("set %q, escrowed %q", pw.set["LocalBoss"], esc.got[0].Password)
	}
	// The password never appears in what is reported.
	for _, field := range []string{res.Stdout, res.Stderr, res.Error} {
		if strings.Contains(field, esc.got[0].Password) {
			t.Fatal("the password leaked into the result")
		}
	}

	// A named account is used as named.
	e.Execute(context.Background(), cmd(t, protocol.CommandRotateAdminPassword,
		protocol.RotateAdminPasswordPayload{Account: "helpdesk", Length: 24}))
	if _, ok := pw.set["helpdesk"]; !ok {
		t.Fatal("the named account wasn't set")
	}
}

func TestRotateNeverSetsWhatWasntEscrowed(t *testing.T) {
	pw := &fakePasswords{builtin: "Administrator", set: map[string]string{}}
	esc := &fakeEscrower{err: errors.New("503 service unavailable")}
	e := &Executor{Passwords: pw, Escrower: esc}
	res := e.Execute(context.Background(), cmd(t, protocol.CommandRotateAdminPassword, nil))
	if res.Status != protocol.ResultFailed || !strings.Contains(res.Error, "wasn't set") {
		t.Fatalf("rotate = %+v", res)
	}
	if len(pw.set) != 0 {
		t.Fatalf("set %v after the escrow failed", pw.set)
	}
}

func TestRotateReportsASetFailure(t *testing.T) {
	pw := &fakePasswords{builtin: "Administrator", set: map[string]string{}, err: errors.New("access denied")}
	e := &Executor{Passwords: pw, Escrower: &fakeEscrower{}}
	res := e.Execute(context.Background(), cmd(t, protocol.CommandRotateAdminPassword, nil))
	if res.Status != protocol.ResultFailed || !strings.Contains(res.Error, "access denied") {
		t.Fatalf("rotate = %+v", res)
	}
	if res := (&Executor{}).Execute(context.Background(), cmd(t, protocol.CommandRotateAdminPassword, nil)); res.Status != protocol.ResultFailed {
		t.Errorf("no setter = %+v", res)
	}
}

func TestGeneratePassword(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		p, err := GeneratePassword(20)
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != 20 || seen[p] {
			t.Fatalf("password %q (len %d, repeat %v)", p, len(p), seen[p])
		}
		seen[p] = true
		for _, alphabet := range passwordAlphabets {
			if !strings.ContainsAny(p, alphabet) {
				t.Fatalf("%q has nothing from %q", p, alphabet)
			}
		}
		if strings.ContainsAny(p, "0O1lI'\"`") {
			t.Fatalf("%q has a look-alike character", p)
		}
	}
}

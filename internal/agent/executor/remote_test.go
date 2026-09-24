package executor

import (
	"bufio"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"retune/internal/opsign"
	"retune/internal/protocol"
)

// fakeChannel plays the server: it hands out queued input and records
// output and how the session ended.
type fakeChannel struct {
	mu     sync.Mutex
	input  []protocol.RemoteChunk
	ended  bool
	output strings.Builder
	endWhy string
	gotOut chan struct{}
}

func (f *fakeChannel) RemoteInput(ctx context.Context, _ string, after int64) (protocol.RemoteInputResponse, error) {
	f.mu.Lock()
	var out []protocol.RemoteChunk
	for _, c := range f.input {
		if c.Seq > after {
			out = append(out, c)
		}
	}
	ended := f.ended
	f.mu.Unlock()
	if len(out) == 0 && !ended {
		select {
		case <-ctx.Done():
			return protocol.RemoteInputResponse{}, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	return protocol.RemoteInputResponse{Chunks: out, Ended: ended}, nil
}

func (f *fakeChannel) RemoteOutput(_ context.Context, _, stream, data string) error {
	f.mu.Lock()
	f.output.WriteString(stream + ":" + data)
	f.mu.Unlock()
	select {
	case f.gotOut <- struct{}{}:
	default:
	}
	return nil
}

func (f *fakeChannel) RemoteEnd(_ context.Context, _, reason string) error {
	f.mu.Lock()
	f.endWhy = reason
	f.mu.Unlock()
	return nil
}

func (f *fakeChannel) say(seq int64, data string) {
	f.mu.Lock()
	f.input = append(f.input, protocol.RemoteChunk{Seq: seq, Stream: protocol.RemoteStreamIn, Data: data})
	f.mu.Unlock()
}

// upperShell reads lines and writes them back in capitals, and exits on
// "exit".
func upperShell(killed *bool) ShellStarter {
	return func(ctx context.Context) (*Shell, error) {
		inR, inW := io.Pipe()
		outR, outW := io.Pipe()
		errR, errW := io.Pipe()
		done := make(chan struct{})
		var once sync.Once
		stop := func() {
			once.Do(func() {
				close(done)
				outW.Close()
				errW.Close()
				inR.Close()
			})
		}
		go func() {
			sc := bufio.NewScanner(inR)
			for sc.Scan() {
				if sc.Text() == "exit" {
					break
				}
				_, _ = io.WriteString(outW, strings.ToUpper(sc.Text())+"\n")
			}
			stop()
		}()
		return &Shell{
			Stdin: inW, Stdout: outR, Stderr: errR,
			Wait: func() error { <-done; return nil },
			Kill: func() { *killed = true; stop() },
		}, nil
	}
}

func remoteCmd(t *testing.T) protocol.Command {
	return cmd(t, protocol.CommandRemoteShell, protocol.RemoteShellPayload{SessionID: "s1"})
}

func TestRemoteShellRelaysAndEndsFromTheConsole(t *testing.T) {
	ch := &fakeChannel{gotOut: make(chan struct{}, 10)}
	killed := false
	e := &Executor{Remote: ch, StartShell: upperShell(&killed)}
	ch.say(1, "hello\n")

	done := make(chan protocol.CommandResult)
	go func() { done <- e.Execute(context.Background(), remoteCmd(t)) }()
	select {
	case <-ch.gotOut:
	case <-time.After(5 * time.Second):
		t.Fatal("no output came back")
	}
	ch.mu.Lock()
	ch.ended = true
	ch.mu.Unlock()
	var res protocol.CommandResult
	select {
	case res = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the session didn't end")
	}
	if !strings.Contains(ch.output.String(), "out:HELLO\n") {
		t.Fatalf("output %q", ch.output.String())
	}
	if !killed || ch.endWhy != "ended from the console" || !strings.Contains(res.Stdout, "ended from the console") {
		t.Fatalf("killed %v, ended %q, result %+v", killed, ch.endWhy, res)
	}
}

func TestRemoteShellEndsWhenTheShellExits(t *testing.T) {
	ch := &fakeChannel{gotOut: make(chan struct{}, 10)}
	killed := false
	e := &Executor{Remote: ch, StartShell: upperShell(&killed)}
	ch.say(1, "exit\n")
	res := e.Execute(context.Background(), remoteCmd(t))
	if ch.endWhy != "the shell exited" || res.Status != protocol.ResultSucceeded {
		t.Fatalf("ended %q, result %+v", ch.endWhy, res)
	}
}

func TestRemoteShellIdleTimeout(t *testing.T) {
	saved := remoteLimits
	remoteLimits.idle = 100 * time.Millisecond
	defer func() { remoteLimits = saved }()
	ch := &fakeChannel{gotOut: make(chan struct{}, 10)}
	killed := false
	e := &Executor{Remote: ch, StartShell: upperShell(&killed)}
	e.Execute(context.Background(), remoteCmd(t))
	if !strings.Contains(ch.endWhy, "nothing was typed") || !killed {
		t.Fatalf("ended %q, killed %v", ch.endWhy, killed)
	}
}

func TestRemoteShellRefusedOnASignedOnlyDevice(t *testing.T) {
	ch := &fakeChannel{gotOut: make(chan struct{}, 10)}
	started := false
	e := &Executor{Remote: ch, Operations: opsign.Policy{Enforced: true},
		StartShell: func(context.Context) (*Shell, error) { started = true; return nil, nil }}
	res := e.Execute(context.Background(), remoteCmd(t))
	if res.Status != protocol.ResultFailed || started || !strings.Contains(ch.endWhy, "only signed code") {
		t.Fatalf("result %+v, started %v, ended %q", res, started, ch.endWhy)
	}
}

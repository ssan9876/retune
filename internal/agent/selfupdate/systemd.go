package selfupdate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// SystemdController is the ServiceController for the Linux systemd unit.
//
// The unit file an administrator installed is never edited. The binary is
// repointed with a drop-in that resets ExecStart, which is also what makes a
// package that replaces the unit file harmless: the drop-in still wins, and
// the administrator can see exactly what self-update changed in one file.
type SystemdController struct {
	Unit      string // retune-agent.service
	DropInDir string // /etc/systemd/system/retune-agent.service.d
	Run       Runner
}

// DropInName is the drop-in self-update owns.
const DropInName = "50-retune-self-update.conf"

func (c *SystemdController) dropIn() string { return filepath.Join(c.DropInDir, DropInName) }

// Config returns the command line the unit runs: the drop-in's, when
// self-update has written one, or else what systemd reports for the unit.
func (c *SystemdController) Config() (string, []string, error) {
	if b, err := os.ReadFile(c.dropIn()); err == nil {
		argv, err := lastExecStart(string(b))
		if err != nil {
			return "", nil, fmt.Errorf("%s: %w", c.dropIn(), err)
		}
		return argv[0], argv[1:], nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", nil, err
	}
	out, err := c.Run(context.Background(), "systemctl", "show", "--property=ExecStart", "--value", c.Unit)
	if err != nil {
		return "", nil, fmt.Errorf("systemctl show %s: %w: %s", c.Unit, err, strings.TrimSpace(string(out)))
	}
	argv, err := parseShowExecStart(string(out))
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", c.Unit, err)
	}
	return argv[0], argv[1:], nil
}

// SetBinPath writes the drop-in and reloads systemd. The drop-in is written
// through a temp file and rename, like the update record: a half-written
// ExecStart would stop the agent starting at all.
func (c *SystemdController) SetBinPath(binPath string, args []string) error {
	if err := os.MkdirAll(c.DropInDir, 0o755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# Written by the Retune agent's self-update. Delete this file to run the\n")
	b.WriteString("# binary the unit itself names again.\n")
	b.WriteString("[Service]\nExecStart=\nExecStart=")
	for i, a := range append([]string{binPath}, args...) {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(systemdQuote(a))
	}
	b.WriteByte('\n')
	tmp := c.dropIn() + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, c.dropIn()); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if out, err := c.Run(context.Background(), "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SetRecoveryActions has nothing to do: the unit Retune ships restarts the
// agent with Restart=always.
func (c *SystemdController) SetRecoveryActions() error { return nil }

// Stop stops the unit; systemctl waits for it to stop.
func (c *SystemdController) Stop(ctx context.Context) error {
	if out, err := c.Run(ctx, "systemctl", "stop", c.Unit); err != nil {
		return fmt.Errorf("systemctl stop %s: %w: %s", c.Unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Start starts the unit.
func (c *SystemdController) Start() error {
	if out, err := c.Run(context.Background(), "systemctl", "start", c.Unit); err != nil {
		return fmt.Errorf("systemctl start %s: %w: %s", c.Unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Running reports whether the unit is active.
func (c *SystemdController) Running() (bool, error) {
	out, err := c.Run(context.Background(), "systemctl", "is-active", c.Unit)
	// is-active exits non-zero for every state but active; that is an answer,
	// not a failure.
	return err == nil && strings.TrimSpace(string(out)) == "active", nil
}

// Close has nothing to release.
func (c *SystemdController) Close() error { return nil }

// parseShowExecStart reads the argv out of `systemctl show -p ExecStart
// --value`, which prints "{ path=... ; argv[]=/bin/x run --data-dir /d ;
// ignore_errors=no ; ... }". systemd does not quote argv there, so arguments
// are split on spaces: the paths Retune uses have none.
func parseShowExecStart(out string) ([]string, error) {
	_, rest, found := strings.Cut(out, "argv[]=")
	if !found {
		return nil, fmt.Errorf("no ExecStart command line in %q", strings.TrimSpace(out))
	}
	line, _, _ := strings.Cut(rest, " ;")
	argv := strings.Fields(line)
	if len(argv) == 0 {
		return nil, errors.New("an empty ExecStart")
	}
	return argv, nil
}

// lastExecStart returns the command line of the last non-empty ExecStart= in
// a unit or drop-in, unquoting what SetBinPath quoted.
func lastExecStart(unit string) ([]string, error) {
	var argv []string
	sc := bufio.NewScanner(strings.NewReader(unit))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		v, found := strings.CutPrefix(line, "ExecStart=")
		if !found || strings.TrimSpace(v) == "" {
			continue
		}
		words, err := systemdSplit(v)
		if err != nil {
			return nil, err
		}
		argv = words
	}
	if len(argv) == 0 {
		return nil, errors.New("no ExecStart command line")
	}
	return argv, nil
}

// systemdQuote quotes one argument for an ExecStart line. Only what systemd
// would otherwise split or interpret needs it; everything else stays bare so
// the drop-in reads like a hand-written one.
func systemdQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"'\\$%;") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `$$`, `%`, `%%`)
	return `"` + r.Replace(s) + `"`
}

// systemdSplit splits an ExecStart value into words, undoing systemdQuote.
func systemdSplit(s string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord, quoted := false, false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case quoted && ch == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		case quoted && ch == '"':
			quoted = false
		case quoted:
			if (ch == '$' || ch == '%') && i+1 < len(s) && s[i+1] == ch {
				i++
			}
			cur.WriteByte(ch)
		case ch == '"':
			quoted, inWord = true, true
		case ch == ' ' || ch == '\t':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteByte(ch)
			inWord = true
		}
	}
	if quoted {
		return nil, fmt.Errorf("an unterminated quote in %q", s)
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}

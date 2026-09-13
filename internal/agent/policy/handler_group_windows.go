//go:build windows

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"retune/internal/protocol"
)

// GroupHandler manages the membership of a local group.
//
// It works through net.exe, which ships with Windows and does exactly this.
// The alternative is the NetLocalGroup family of Win32 calls, which is a great
// deal of syscall plumbing for the same result.
type GroupHandler struct {
	// Run executes a command and returns its combined output. Tests replace it.
	Run func(ctx context.Context, name string, args ...string) (string, error)
}

func (GroupHandler) Kind() string { return protocol.KindGroup }

func (h GroupHandler) run(ctx context.Context, name string, args ...string) (string, error) {
	if h.Run != nil {
		return h.Run(ctx, name, args...)
	}
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// builtinAdministrator is never removed by an exact-mode setting. Locking every
// administrator out of a machine is not a configuration a management tool
// should carry out, whatever the profile says.
const builtinAdministrator = "administrator"

// Members lists a local group's members.
func (h GroupHandler) Members(ctx context.Context, group string) ([]string, error) {
	out, err := h.run(ctx, "net", "localgroup", group)
	if err != nil {
		return nil, err
	}
	return parseNetLocalGroup(out), nil
}

// parseNetLocalGroup reads the member list out of net localgroup's output,
// which puts the members between a line of dashes and "The command completed".
func parseNetLocalGroup(out string) []string {
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	started := false
	var members []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "----"):
			started = true
		case !started:
		case trimmed == "" || strings.HasPrefix(trimmed, "The command completed"):
		default:
			members = append(members, trimmed)
		}
	}
	return members
}

func sameMember(a, b string) bool {
	return strings.EqualFold(bareName(a), bareName(b)) || strings.EqualFold(a, b)
}

// bareName drops a domain prefix, so CONTOSO\Ops and Ops compare as one.
func bareName(name string) string {
	if i := strings.LastIndex(name, `\`); i >= 0 {
		return name[i+1:]
	}
	return name
}

func containsMember(list []string, want string) bool {
	for _, got := range list {
		if sameMember(got, want) {
			return true
		}
	}
	return false
}

func (h GroupHandler) Get(ctx context.Context, s protocol.Setting) (State, error) {
	members, err := h.Members(ctx, s.Group)
	if err != nil {
		return State{}, nil // the group does not exist, so there is nothing to restore
	}
	raw, err := json.Marshal(members)
	if err != nil {
		return State{}, err
	}
	return State{Exists: true, Data: raw}, nil
}

func (h GroupHandler) Test(ctx context.Context, s protocol.Setting) (bool, error) {
	members, err := h.Members(ctx, s.Group)
	if err != nil {
		return false, err
	}
	for _, want := range s.Members {
		if !containsMember(members, want) {
			return false, nil
		}
	}
	if s.Mode != protocol.ModeExact {
		return true, nil
	}
	for _, got := range members {
		if strings.EqualFold(bareName(got), builtinAdministrator) {
			continue
		}
		if !containsMember(s.Members, got) {
			return false, nil
		}
	}
	return true, nil
}

func (h GroupHandler) Set(ctx context.Context, s protocol.Setting) error {
	members, err := h.Members(ctx, s.Group)
	if err != nil {
		return err
	}
	for _, want := range s.Members {
		if containsMember(members, want) {
			continue
		}
		if _, err := h.run(ctx, "net", "localgroup", s.Group, want, "/add"); err != nil {
			return err
		}
	}
	if s.Mode != protocol.ModeExact {
		return nil
	}
	for _, got := range members {
		if strings.EqualFold(bareName(got), builtinAdministrator) {
			// Never remove the built-in Administrator.
			continue
		}
		if containsMember(s.Members, got) {
			continue
		}
		if _, err := h.run(ctx, "net", "localgroup", s.Group, got, "/delete"); err != nil {
			return err
		}
	}
	return nil
}

// Revert restores the membership as it was found.
func (h GroupHandler) Revert(ctx context.Context, s protocol.Setting, prior State) error {
	if !prior.Exists || len(prior.Data) == 0 {
		return nil
	}
	var was []string
	if err := json.Unmarshal(prior.Data, &was); err != nil {
		return err
	}
	// Putting the old list back is exactly an exact-mode apply of it.
	return h.Set(ctx, protocol.Setting{
		Kind: protocol.KindGroup, Group: s.Group, Members: was, Mode: protocol.ModeExact,
	})
}

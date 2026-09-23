package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/commands"
)

const commandUsage = `usage: retune-server command queue --device <id> --type <type> [flags] | command show <id>`

func commandCmd(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(commandUsage)
	}
	switch args[0] {
	case "queue":
		return commandQueue(ctx, args[1:], getenv, out)
	case "show":
		id, err := oneID(args[1:])
		if err != nil {
			return err
		}
		return commandShow(ctx, id, getenv, out)
	default:
		return errors.New(commandUsage)
	}
}

func commandQueue(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	fs := flag.NewFlagSet("command queue", flag.ContinueOnError)
	device := fs.String("device", "", "device ID")
	typ := fs.String("type", "", "run_powershell | restart | refresh_inventory | lock | collect_logs | wipe")
	script := fs.String("script", "", "PowerShell script text")
	scriptFile := fs.String("script-file", "", "path to a .ps1 file")
	timeout := fs.Duration("timeout", commands.DefaultScriptTimeout, "script timeout")
	delay := fs.Duration("delay", time.Minute, "restart delay")
	message := fs.String("message", "", "restart message shown to the user")
	ttl := fs.Duration("ttl", commands.DefaultTTL, "how long the command stays deliverable")
	hours := fs.Int("hours", protocol.DefaultLogHours, "collect_logs: how many hours of event logs")
	protected := fs.Bool("protected", false, "wipe: also remove what a reset keeps for recovery")
	confirm := fs.String("confirm-hostname", "", "wipe: the device's hostname, to confirm")
	reason := fs.String("reason", "", "wipe: why")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := uuid.Parse(*device)
	if err != nil {
		return errors.New("--device must be a device ID")
	}

	var payload json.RawMessage
	switch *typ {
	case protocol.CommandRunPowerShell:
		body := *script
		if *scriptFile != "" {
			b, err := os.ReadFile(*scriptFile)
			if err != nil {
				return err
			}
			body = string(b)
		}
		payload, err = json.Marshal(protocol.RunPowerShellPayload{Script: body, TimeoutSeconds: int(timeout.Seconds())})
	case protocol.CommandRestart:
		payload, err = json.Marshal(protocol.RestartPayload{DelaySeconds: int(delay.Seconds()), Message: *message})
	case protocol.CommandRefreshInventory, protocol.CommandLock:
	case protocol.CommandCollectLogs:
		payload, err = json.Marshal(protocol.CollectLogsPayload{Hours: *hours})
	case protocol.CommandWipe:
		payload, err = json.Marshal(protocol.WipePayload{Protected: *protected})
	default:
		return errors.New("--type must be one of run_powershell, restart, refresh_inventory, lock, collect_logs, wipe")
	}
	if err != nil {
		return err
	}

	st, err := openStore(ctx, getenv)
	if err != nil {
		return err
	}
	defer st.Close()

	svc := &commands.Service{Store: st, Now: time.Now}
	c, err := svc.Queue(ctx, commands.QueueOptions{
		DeviceID: id, Type: *typ, Payload: payload, CreatedBy: "cli", TTL: *ttl,
		ConfirmHostname: *confirm, Reason: *reason,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Command ID: %s\nQueued for device %s; expires %s.\n", c.ID, id, c.ExpiresAt.Format(time.RFC3339))
	return nil
}

func commandShow(ctx context.Context, id uuid.UUID, getenv func(string) string, out io.Writer) error {
	st, err := openStore(ctx, getenv)
	if err != nil {
		return err
	}
	defer st.Close()

	c, res, err := (&commands.Service{Store: st, Now: time.Now}).Get(ctx, id)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "ID:        %s\nDevice:    %s\nType:      %s\nStatus:    %s\nPayload:   %s\n",
		c.ID, c.DeviceID, c.Type, c.Status, c.Payload)
	fmt.Fprintf(out, "Created:   %s by %s\nDelivered: %s\nStarted:   %s\nCompleted: %s\nExpires:   %s\n",
		c.CreatedAt.Format(time.RFC3339), c.CreatedBy, timeOrNever(c.DeliveredAt), timeOrNever(c.StartedAt),
		timeOrNever(c.CompletedAt), c.ExpiresAt.Format(time.RFC3339))
	if res == nil {
		fmt.Fprintln(out, "Result:    none yet")
		return nil
	}
	fmt.Fprintf(out, "\nExit code: %d\nDuration:  %s\n", res.ExitCode, res.FinishedAt.Sub(res.StartedAt).Round(time.Millisecond))
	if res.Error != "" {
		fmt.Fprintf(out, "Error:     %s\n", res.Error)
	}
	printOutput(out, "stdout", res.Stdout, res.StdoutTruncated)
	printOutput(out, "stderr", res.Stderr, res.StderrTruncated)
	return nil
}

func printOutput(out io.Writer, name, body string, truncated bool) {
	if body == "" {
		return
	}
	fmt.Fprintf(out, "\n--- %s", name)
	if truncated {
		fmt.Fprint(out, " (truncated)")
	}
	fmt.Fprintf(out, " ---\n%s\n", body)
}

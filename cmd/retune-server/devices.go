package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/devices"
	"retune/internal/server/store"
)

const deviceUsage = `usage: retune-server device list | show <id> | retire <id> | unenroll <id>`

func deviceCmd(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(deviceUsage)
	}
	var id uuid.UUID
	if args[0] != "list" {
		var err error
		if id, err = oneID(args[1:]); err != nil {
			return err
		}
	}
	st, err := openStore(ctx, getenv)
	if err != nil {
		return err
	}
	defer st.Close()

	switch args[0] {
	case "list":
		return deviceList(ctx, st, out)
	case "show":
		return deviceShow(ctx, st, id, out)
	case "retire":
		if err := (&devices.Service{Store: st}).Retire(ctx, id, "cli"); err != nil {
			return err
		}
		fmt.Fprintf(out, "Device %s retired.\n", id)
		return nil
	case "unenroll":
		if err := (&devices.Service{Store: st}).Unenroll(ctx, id, "cli"); err != nil {
			return err
		}
		fmt.Fprintf(out, "Device %s unenrolled; its agent will wipe its identity at the next check-in.\n", id)
		return nil
	default:
		return errors.New(deviceUsage)
	}
}

func oneID(args []string) (uuid.UUID, error) {
	if len(args) != 1 {
		return uuid.UUID{}, errors.New("expected exactly one device ID")
	}
	id, err := uuid.Parse(args[0])
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("invalid device ID %q", args[0])
	}
	return id, nil
}

func deviceList(ctx context.Context, st *store.Store, out io.Writer) error {
	list, err := st.Q().ListDevices(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tHOSTNAME\tSTATUS\tOS\tLAST SEEN")
	for _, d := range list {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", d.ID, d.Hostname, d.Status, orDash(d.OSVersion), timeOrNever(d.LastSeenAt))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(out, "\n%d device(s).\n", len(list))
	return nil
}

func deviceShow(ctx context.Context, st *store.Store, id uuid.UUID, out io.Writer) error {
	q := st.Q()
	d, err := q.GetDevice(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no device %s", id)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "ID:            %s\nHostname:      %s\nStatus:        %s\n", d.ID, d.Hostname, d.Status)
	fmt.Fprintf(out, "OS:            %s (build %s)\nHardware:      %s %s\nSerial:        %s\nSMBIOS UUID:   %s\n",
		orDash(d.OSVersion), orDash(d.OSBuild), orDash(d.Manufacturer), orDash(d.Model), orDash(d.Serial), orDash(d.SMBIOSUUID))
	fmt.Fprintf(out, "Agent version: %s\nEnrolled:      %s\nLast seen:     %s\nCert expires:  %s\n",
		orDash(d.AgentVersion), d.EnrolledAt.Format(time.RFC3339), timeOrNever(d.LastSeenAt), d.CertExpiresAt.Format(time.RFC3339))

	inv, err := q.GetInventory(ctx, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		fmt.Fprintln(out, "Inventory:     none yet")
	case err != nil:
		return err
	default:
		sw, err := q.ListSoftware(ctx, id)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Inventory:     collected %s, %.1f GB RAM, %.1f GB free, %d package(s)\n",
			inv.CollectedAt.Format(time.RFC3339), inv.RAMGB, inv.DiskFreeGB, len(sw))
	}

	cmds, err := q.ListCommands(ctx, id, 10)
	if err != nil {
		return err
	}
	if len(cmds) == 0 {
		fmt.Fprintln(out, "Commands:      none")
		return nil
	}
	fmt.Fprintln(out, "\nRecent commands:")
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTYPE\tSTATUS\tCREATED")
	for _, c := range cmds {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", c.ID, c.Type, c.Status, c.CreatedAt.Format(time.RFC3339))
	}
	return tw.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func timeOrNever(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.Format(time.RFC3339)
}

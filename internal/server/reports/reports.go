// Package reports emails the fleet's CSV exports on a schedule, so auditors
// and managers get the numbers without a console account.
package reports

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	// Time zones are named by the admin; the server may run where the
	// system has no zone database, such as a scratch container.
	_ "time/tzdata"

	"retune/internal/server/alerts"
	"retune/internal/server/csvexport"
	"retune/internal/server/store"
)

// Frequencies.
const (
	Daily  = "daily"
	Weekly = "weekly"
)

// MaxAttachment is the largest CSV sent by email. Past it, the message says
// to download the export from the console instead: many relays refuse
// messages much bigger.
const MaxAttachment = 10 << 20

// ErrBadSchedule is a schedule that can't be run.
var ErrBadSchedule = errors.New("invalid schedule")

// Schedule is when a report is sent: every day, or one day a week, at an
// hour in a time zone.
type Schedule struct {
	Frequency string
	Weekday   int // 0 Sunday … 6 Saturday; weekly only
	Hour      int
	Timezone  string
}

// Validate checks a schedule, including that its time zone is one the
// server knows.
func (s Schedule) Validate() error {
	if s.Frequency != Daily && s.Frequency != Weekly {
		return fmt.Errorf("%w: frequency must be daily or weekly", ErrBadSchedule)
	}
	if s.Weekday < 0 || s.Weekday > 6 {
		return fmt.Errorf("%w: weekday must be 0 (Sunday) to 6 (Saturday)", ErrBadSchedule)
	}
	if s.Hour < 0 || s.Hour > 23 {
		return fmt.Errorf("%w: hour must be 0 to 23", ErrBadSchedule)
	}
	if _, err := time.LoadLocation(s.Timezone); err != nil || s.Timezone == "" || s.Timezone == "Local" {
		return fmt.Errorf("%w: %q is not a time zone name such as UTC or Europe/London", ErrBadSchedule, s.Timezone)
	}
	return nil
}

// Next is the first time after after that the schedule falls on.
func (s Schedule) Next(after time.Time) (time.Time, error) {
	loc, err := time.LoadLocation(s.Timezone)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %v", ErrBadSchedule, err)
	}
	local := after.In(loc)
	day := time.Date(local.Year(), local.Month(), local.Day(), s.Hour, 0, 0, 0, loc)
	for range 8 {
		if day.After(after) && (s.Frequency == Daily || int(day.Weekday()) == s.Weekday) {
			return day, nil
		}
		day = time.Date(day.Year(), day.Month(), day.Day()+1, s.Hour, 0, 0, 0, loc)
	}
	return time.Time{}, fmt.Errorf("%w: no time found", ErrBadSchedule)
}

// ScheduleOf is a stored report's schedule.
func ScheduleOf(r store.ScheduledReport) Schedule {
	return Schedule{Frequency: r.Frequency, Weekday: r.Weekday, Hour: r.Hour, Timezone: r.Timezone}
}

// Service builds and sends reports.
type Service struct {
	Store  *store.Store
	Mailer alerts.AttachmentMailer
	Now    func() time.Time
	Log    *slog.Logger
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// SendDue sends every report that is due, and reports how many were sent.
// A report that fails is tried again at its next scheduled time, with the
// error kept for the console to show, rather than every minute until the
// relay recovers.
func (s *Service) SendDue(ctx context.Context) (int64, error) {
	now := s.now()
	var sent int64
	err := s.Store.InTx(ctx, func(q *store.Queries) error {
		due, err := q.DueReports(ctx, now)
		if err != nil {
			return err
		}
		for _, r := range due {
			sendErr := s.send(ctx, q, r, now)
			next, err := ScheduleOf(r).Next(now)
			if err != nil {
				return err
			}
			var sentAt *time.Time
			lastError := ""
			if sendErr != nil {
				lastError = sendErr.Error()
				if s.Log != nil {
					s.Log.Warn("scheduled report failed", "report", r.Name, "error", sendErr)
				}
			} else {
				sentAt = &now
				sent++
			}
			if err := q.RecordReportRun(ctx, r.ID, next, sentAt, lastError); err != nil {
				return err
			}
		}
		return nil
	})
	return sent, err
}

// SendNow sends one report at once, off its schedule, recording the result.
func (s *Service) SendNow(ctx context.Context, r store.ScheduledReport) error {
	now := s.now()
	sendErr := s.send(ctx, s.Store.Q(), r, now)
	var sentAt *time.Time
	lastError := ""
	if sendErr != nil {
		lastError = sendErr.Error()
	} else {
		sentAt = &now
	}
	if err := s.Store.Q().RecordReportRun(ctx, r.ID, r.NextRunAt, sentAt, lastError); err != nil {
		return err
	}
	return sendErr
}

// send builds a report's CSV and emails it.
func (s *Service) send(ctx context.Context, q *store.Queries, r store.ScheduledReport, now time.Time) error {
	if s.Mailer == nil {
		return alerts.ErrNoSMTP
	}
	var buf bytes.Buffer
	date := now.UTC().Format("2006-01-02")
	var name, what string
	switch r.Kind {
	case store.ReportDevices:
		if err := csvexport.WriteDevices(ctx, q, nil, &buf); err != nil {
			return err
		}
		name, what = "devices-"+date+".csv", "every device"
	case store.ReportCompliance:
		if r.PolicyID == nil {
			return errors.New("a compliance report names a policy")
		}
		policy, err := q.GetCompliancePolicy(ctx, store.DefaultTenantID, *r.PolicyID)
		if err != nil {
			return fmt.Errorf("the report's compliance policy: %w", err)
		}
		if err := csvexport.WritePolicyDevices(ctx, q, *r.PolicyID, r.State, nil, &buf); err != nil {
			return err
		}
		name = "compliance-" + fileSafe(policy.Name) + "-" + date + ".csv"
		what = "each device's result on the compliance policy " + policy.Name
		if r.State != "" {
			what += ", " + strings.ReplaceAll(r.State, "_", " ") + " devices only"
		}
	default:
		return fmt.Errorf("unknown report kind %q", r.Kind)
	}
	rows := bytes.Count(buf.Bytes(), []byte("\n")) - 1
	body := fmt.Sprintf("%s\n\nThis report lists %s: %d rows, as of %s.\n\n"+
		"It is sent by Retune on a schedule an administrator set up. To stop receiving it, ask them to remove you from it.\n",
		r.Name, what, max(rows, 0), now.UTC().Format("2 January 2006 15:04 MST"))
	var files []alerts.Attachment
	if buf.Len() <= MaxAttachment {
		files = []alerts.Attachment{{Name: name, ContentType: "text/csv", Data: buf.Bytes()}}
	} else {
		body += fmt.Sprintf("\nThe CSV is %d MB, too large to attach. Download it from the Retune console instead.\n", buf.Len()>>20)
	}
	return s.Mailer.SendWithAttachments(ctx, r.Recipients, "Retune report: "+r.Name, body, files)
}

func fileSafe(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
				b.WriteByte('-')
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

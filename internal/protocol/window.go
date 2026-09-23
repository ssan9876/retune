package protocol

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// ItemKindWindow is a maintenance window assigned to a group. A device with
// any runs script deployments, app installs and removals, and agent updates
// only inside one of them. Commands and configuration profiles are not held:
// a command is somebody asking for something now, and a profile keeps a
// setting true rather than making a change.
const ItemKindWindow = "window"

// weekdays are the day names a window uses, in time.Weekday order.
var weekdays = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

// Window is when changes may be made to a device, in the device's own local
// time: from Start for DurationMinutes, on each of Days (every day if none).
// A window may run past midnight into the next day.
type Window struct {
	Days            []string `json:"days,omitempty"`
	Start           string   `json:"start"`
	DurationMinutes int      `json:"duration_minutes"`
}

// Validate checks a window and normalizes its day names to lower case.
func (w *Window) Validate() error {
	if _, _, err := w.startClock(); err != nil {
		return err
	}
	if w.DurationMinutes < 1 || w.DurationMinutes > 24*60 {
		return fmt.Errorf("%w: duration_minutes must be between 1 and 1440", ErrBadOptions)
	}
	seen := map[string]bool{}
	days := make([]string, 0, len(w.Days))
	for _, d := range w.Days {
		d = strings.ToLower(strings.TrimSpace(d))
		if !slices.Contains(weekdays, d) {
			return fmt.Errorf("%w: days must be mon, tue, wed, thu, fri, sat or sun, not %q", ErrBadOptions, d)
		}
		if !seen[d] {
			seen[d] = true
			days = append(days, d)
		}
	}
	w.Days = days
	return nil
}

func (w Window) startClock() (hour, minute int, err error) {
	t, err := time.Parse("15:04", w.Start)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: start must be a time of day as HH:MM, like 22:00", ErrBadOptions)
	}
	return t.Hour(), t.Minute(), nil
}

// Contains reports whether t falls inside the window, in t's own location.
func (w Window) Contains(t time.Time) bool {
	hour, minute, err := w.startClock()
	if err != nil || w.DurationMinutes < 1 {
		return false
	}
	length := time.Duration(w.DurationMinutes) * time.Minute
	// Today's opening, and yesterday's, which may run past midnight.
	for _, back := range []int{0, -1} {
		day := t.AddDate(0, 0, back)
		start := time.Date(day.Year(), day.Month(), day.Day(), hour, minute, 0, 0, t.Location())
		if !w.onDay(start.Weekday()) {
			continue
		}
		if !t.Before(start) && t.Before(start.Add(length)) {
			return true
		}
	}
	return false
}

func (w Window) onDay(d time.Weekday) bool {
	return len(w.Days) == 0 || slices.Contains(w.Days, weekdays[d])
}

// Windows is what a check-in says about when this device may be changed.
type Windows struct {
	// Assigned is whether any window applies at all; with none, any time will
	// do.
	Assigned bool
	Valid    []Window
}

// WindowsFrom collects the maintenance windows among a check-in's items. A
// window the agent can't read still counts as assigned, and is never open:
// holding changes back is the safe way to misunderstand one.
func WindowsFrom(items []Item) Windows {
	var ws Windows
	for _, it := range items {
		if it.Kind != ItemKindWindow {
			continue
		}
		ws.Assigned = true
		var w Window
		if err := json.Unmarshal(it.Options, &w); err != nil || w.Validate() != nil {
			continue
		}
		ws.Valid = append(ws.Valid, w)
	}
	return ws
}

// Open reports whether changes may be made at t.
func (ws Windows) Open(t time.Time) bool {
	if !ws.Assigned {
		return true
	}
	for _, w := range ws.Valid {
		if w.Contains(t) {
			return true
		}
	}
	return false
}

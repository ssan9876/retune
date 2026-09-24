package protocol

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestWindowValidate(t *testing.T) {
	good := Window{Days: []string{" Sat", "sun", "sat"}, Start: "22:00", DurationMinutes: 240}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(good.Days) != 2 || good.Days[0] != "sat" || good.Days[1] != "sun" {
		t.Fatalf("days = %v", good.Days)
	}
	for _, bad := range []Window{
		{Start: "25:00", DurationMinutes: 60},
		{Start: "10pm", DurationMinutes: 60},
		{Start: "22:00", DurationMinutes: 0},
		{Start: "22:00", DurationMinutes: 1441},
		{Days: []string{"someday"}, Start: "22:00", DurationMinutes: 60},
	} {
		if err := bad.Validate(); !errors.Is(err, ErrBadOptions) {
			t.Errorf("%+v: %v, want ErrBadOptions", bad, err)
		}
	}
}

func TestWindowContains(t *testing.T) {
	loc := time.FixedZone("test", -5*3600)
	at := func(day, hour, minute int) time.Time { return time.Date(2026, 9, day, hour, minute, 0, 0, loc) }
	// 2026-09-26 is a Saturday.
	w := Window{Days: []string{"sat"}, Start: "22:00", DurationMinutes: 240}
	cases := []struct {
		t    time.Time
		want bool
	}{
		{at(26, 21, 59), false},
		{at(26, 22, 0), true},
		{at(26, 23, 30), true},
		{at(27, 1, 59), true}, // Sunday morning, still Saturday's window
		{at(27, 2, 0), false},
		{at(27, 22, 30), false}, // Sunday's evening: not a window day
		{at(25, 22, 30), false}, // Friday
	}
	for _, c := range cases {
		if got := w.Contains(c.t); got != c.want {
			t.Errorf("Contains(%s) = %v, want %v", c.t.Format("Mon 15:04"), got, c.want)
		}
	}
	every := Window{Start: "02:00", DurationMinutes: 60}
	if !every.Contains(at(23, 2, 30)) || every.Contains(at(23, 3, 0)) {
		t.Error("a window with no days is every day")
	}
}

func TestWindowsOpen(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	item := func(kind string, opts any) Item {
		raw, _ := json.Marshal(opts)
		return Item{Kind: kind, ID: "x", Options: raw}
	}
	if !WindowsFrom([]Item{item(ItemKindScript, map[string]any{})}).Open(now) {
		t.Error("no windows: always open")
	}
	noon := Window{Start: "11:00", DurationMinutes: 120}
	night := Window{Start: "22:00", DurationMinutes: 60}
	if !WindowsFrom([]Item{item(ItemKindWindow, night), item(ItemKindWindow, noon)}).Open(now) {
		t.Error("open inside any one of them")
	}
	if WindowsFrom([]Item{item(ItemKindWindow, night)}).Open(now) {
		t.Error("closed outside them all")
	}
	// A window that can't be read is assigned but never open.
	if WindowsFrom([]Item{item(ItemKindWindow, map[string]any{"start": "soon"})}).Open(now) {
		t.Error("an unreadable window must hold changes back")
	}
}

func TestValidComputerName(t *testing.T) {
	for _, good := range []string{"PC1", "LAPTOP-042", "a", "ABCDEFGHIJKLMNO"} {
		if !ValidComputerName(good) {
			t.Errorf("%q should be valid", good)
		}
	}
	for _, bad := range []string{"", "12345", "-PC", "PC-", "ABCDEFGHIJKLMNOP", "PC 1", "PC_1", "PC.corp", "PC'1"} {
		if ValidComputerName(bad) {
			t.Errorf("%q should be refused", bad)
		}
	}
}

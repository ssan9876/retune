package reports

import (
	"errors"
	"testing"
	"time"
)

func TestScheduleNext(t *testing.T) {
	utc := func(s string) time.Time {
		tm, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return tm
	}
	cases := []struct {
		name  string
		s     Schedule
		after string
		want  string
	}{
		{"daily, later today", Schedule{Frequency: Daily, Hour: 7, Timezone: "UTC"}, "2026-09-23T05:00:00Z", "2026-09-23T07:00:00Z"},
		{"daily, exactly on the hour goes to tomorrow", Schedule{Frequency: Daily, Hour: 7, Timezone: "UTC"}, "2026-09-23T07:00:00Z", "2026-09-24T07:00:00Z"},
		// 2026-09-23 is a Wednesday; Monday is 1.
		{"weekly, next Monday", Schedule{Frequency: Weekly, Weekday: 1, Hour: 6, Timezone: "UTC"}, "2026-09-23T05:00:00Z", "2026-09-28T06:00:00Z"},
		{"weekly, later the same day", Schedule{Frequency: Weekly, Weekday: 3, Hour: 9, Timezone: "UTC"}, "2026-09-23T05:00:00Z", "2026-09-23T09:00:00Z"},
		{"in a time zone", Schedule{Frequency: Daily, Hour: 8, Timezone: "America/New_York"}, "2026-09-23T13:00:00Z", "2026-09-24T12:00:00Z"},
		// London moves to GMT on 2026-10-25: 07:00 local is 06:00 UTC before
		// and 07:00 UTC after.
		{"across a clock change", Schedule{Frequency: Daily, Hour: 7, Timezone: "Europe/London"}, "2026-10-24T08:00:00Z", "2026-10-25T07:00:00Z"},
	}
	for _, c := range cases {
		got, err := c.s.Next(utc(c.after))
		if err != nil || !got.Equal(utc(c.want)) {
			t.Errorf("%s: %s, %v; want %s", c.name, got.UTC().Format(time.RFC3339), err, c.want)
		}
	}
}

func TestScheduleValidate(t *testing.T) {
	if err := (Schedule{Frequency: Weekly, Weekday: 5, Hour: 23, Timezone: "Asia/Tokyo"}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Schedule{
		{Frequency: "hourly", Hour: 1, Timezone: "UTC"},
		{Frequency: Daily, Hour: 24, Timezone: "UTC"},
		{Frequency: Weekly, Weekday: 7, Hour: 1, Timezone: "UTC"},
		{Frequency: Daily, Hour: 1, Timezone: "Mars/Olympus"},
		{Frequency: Daily, Hour: 1, Timezone: ""},
	} {
		if err := bad.Validate(); !errors.Is(err, ErrBadSchedule) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

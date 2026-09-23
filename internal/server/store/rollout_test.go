package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func TestRolloutCurrentAndFullAt(t *testing.T) {
	since := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	r := store.Rollout{Percent: 10, StepPercent: 25, StepHours: 24}
	for _, c := range []struct {
		after time.Duration
		want  int
	}{{0, 10}, {23 * time.Hour, 10}, {24 * time.Hour, 35}, {72 * time.Hour, 85}, {96 * time.Hour, 100}, {1000 * time.Hour, 100}} {
		if got := r.Current(since, since.Add(c.after)); got != c.want {
			t.Errorf("after %s: %d%%, want %d%%", c.after, got, c.want)
		}
	}
	if full := r.FullAt(since); !full.Equal(since.Add(96 * time.Hour)) {
		t.Errorf("full at %s", full)
	}
	if !(store.Rollout{Percent: 10}).FullAt(since).IsZero() {
		t.Error("a rollout with no steps never widens by itself")
	}
	if (store.Rollout{}).Current(since, since) != 100 || (store.Rollout{Percent: 100}).Phased() {
		t.Error("the zero rollout, and 100%, is the whole group")
	}
}

// Buckets spread devices evenly and keep them in place as a rollout widens.
func TestRolloutBuckets(t *testing.T) {
	item := uuid.New()
	admitted := map[int]int{}
	for range 10000 {
		d := uuid.New()
		for _, p := range []int{10, 50} {
			if store.RolloutAdmits(item, d, p) {
				admitted[p]++
			}
		}
		if store.RolloutAdmits(item, d, 10) && !store.RolloutAdmits(item, d, 50) {
			t.Fatal("a device inside 10% must be inside 50%")
		}
		if store.RolloutBucket(item, d) != store.RolloutBucket(item, d) {
			t.Fatal("a bucket must not change")
		}
	}
	if admitted[10] < 800 || admitted[10] > 1200 || admitted[50] < 4700 || admitted[50] > 5300 {
		t.Errorf("admitted %v of 10000, want about 1000 and 5000", admitted)
	}
}

// A phased include reaches only its share of the group; a full include of
// the same item through another group reaches the rest.
func TestEffectiveItemsHonoursRollouts(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	now := time.Now()
	item := uuid.Must(uuid.NewV7())

	// Find one device inside a 30% rollout of item and one outside it.
	var in, out store.Device
	for i := 0; in.ID == uuid.Nil || out.ID == uuid.Nil; i++ {
		d := newDevice(t, q, "PC-"+uuid.NewString()[:8])
		if store.RolloutAdmits(item, d.ID, 30) {
			if in.ID == uuid.Nil {
				in = d
			}
		} else if out.ID == uuid.Nil {
			out = d
		}
	}
	mkGroup := func(name string, members ...uuid.UUID) uuid.UUID {
		g := store.Group{ID: uuid.Must(uuid.NewV7()), Name: name, Kind: store.GroupStatic, CreatedAt: now, UpdatedAt: now}
		if err := q.CreateGroup(ctx, g); err != nil {
			t.Fatal(err)
		}
		for _, m := range members {
			if err := q.AddGroupMember(ctx, g.ID, m, now); err != nil {
				t.Fatal(err)
			}
		}
		return g.ID
	}
	assign := func(group uuid.UUID, r store.Rollout, at time.Time) {
		if _, err := q.CreateAssignment(ctx, store.Assignment{
			ID: uuid.Must(uuid.NewV7()), ItemKind: "script", ItemID: item, GroupID: group,
			Mode: store.ModeInclude, CreatedAt: at, CreatedBy: "t", Rollout: r,
		}); err != nil {
			t.Fatal(err)
		}
	}
	has := func(d store.Device, at time.Time) bool {
		items, err := q.EffectiveItems(ctx, d.ID, at)
		if err != nil {
			t.Fatal(err)
		}
		return len(items) == 1
	}

	fleet := mkGroup("Fleet", in.ID, out.ID)
	assign(fleet, store.Rollout{Percent: 30, StepPercent: 70, StepHours: 24}, now)
	if !has(in, now) || has(out, now) {
		t.Fatal("at 30% only the device inside the rollout should have it")
	}
	if !has(out, now.Add(25*time.Hour)) {
		t.Fatal("a day later the rollout is at 100% and reaches everyone")
	}
	// A full include through another group wins over the phased one, even
	// though the phased one is newer.
	assign(fleet, store.Rollout{Percent: 30}, now)
	assign(mkGroup("Pilot", out.ID), store.Rollout{}, now.Add(-time.Hour))
	if !has(out, now) {
		t.Fatal("the pilot group's full include should reach the device outside the rollout")
	}
	got, err := q.ListAssignments(ctx, "script", item)
	if err != nil || len(got) != 2 {
		t.Fatalf("assignments = %v, %v", got, err)
	}
	for _, a := range got {
		if a.GroupID == fleet && a.Rollout.Percent != 30 {
			t.Errorf("fleet rollout = %+v", a.Rollout)
		}
	}
}

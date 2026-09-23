package store

import (
	"hash/fnv"
	"time"

	"github.com/google/uuid"
)

// Rollout is how much of its group an include assignment reaches: Percent at
// first, then StepPercent more every StepHours, counted from when the
// assignment was made or last replaced. The zero value is the whole group.
type Rollout struct {
	Percent     int
	StepPercent int
	StepHours   int
}

// Phased reports whether the rollout holds any of the group back, now or
// ever did.
func (r Rollout) Phased() bool { return r.Percent > 0 && r.Percent < 100 }

// Current is the percentage of the group reached at now, for an assignment
// made at since.
func (r Rollout) Current(since, now time.Time) int {
	if !r.Phased() {
		return 100
	}
	p := r.Percent
	if r.StepPercent > 0 && r.StepHours > 0 && now.After(since) {
		steps := int(now.Sub(since) / (time.Duration(r.StepHours) * time.Hour))
		p += steps * r.StepPercent
	}
	return min(p, 100)
}

// FullAt is when the rollout reaches the whole group, or the zero time if it
// never will without being changed.
func (r Rollout) FullAt(since time.Time) time.Time {
	if !r.Phased() {
		return since
	}
	if r.StepPercent <= 0 || r.StepHours <= 0 {
		return time.Time{}
	}
	steps := (100 - r.Percent + r.StepPercent - 1) / r.StepPercent
	return since.Add(time.Duration(steps*r.StepHours) * time.Hour)
}

// RolloutBucket places a device in 0-99 for one item. It depends only on the
// two ids, so a device keeps its place as a rollout widens - the devices that
// had the item still have it - and the same devices go first for an item
// whichever group it is assigned through.
func RolloutBucket(itemID, deviceID uuid.UUID) int {
	h := fnv.New64a()
	h.Write(itemID[:])
	h.Write(deviceID[:])
	return int(h.Sum64() % 100)
}

// Admits reports whether a rollout at percent reaches the device.
func RolloutAdmits(itemID, deviceID uuid.UUID, percent int) bool {
	return percent >= 100 || RolloutBucket(itemID, deviceID) < percent
}

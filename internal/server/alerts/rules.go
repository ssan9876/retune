// Package alerts evaluates alert rules over what the server already knows and
// delivers what changed to a notification channel.
package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
)

// ErrBadRule is returned for a rule the caller can fix: an unsupported kind,
// a parameter out of range, a field that belongs to some other kind.
var ErrBadRule = errors.New("invalid alert rule")

// maxStaleHours is a year. Past that the rule is not saying "tell me when a
// machine goes quiet", it is saying nothing at all.
const maxStaleHours = 8760

// Params is every rule kind's parameters in one value; each kind reads only
// its own. Parsing is strict, so a `hours` left on a compliance rule is an
// error rather than a setting that silently does nothing.
type Params struct {
	// PolicyID narrows device_non_compliant to one policy. Nil means any.
	PolicyID *uuid.UUID
	// Hours is device_stale's threshold.
	Hours int
	// ItemKind narrows deployment_failed to one kind. Empty means any.
	ItemKind string
}

// allowedFields names each kind's own parameters, so a field that belongs to
// another kind is rejected by name rather than ignored.
func allowedFields(kind string) (fields map[string]bool, ok bool) {
	switch kind {
	case store.AlertDeviceNonCompliant:
		return map[string]bool{"policy_id": true}, true
	case store.AlertDeviceStale:
		return map[string]bool{"hours": true}, true
	case store.AlertDeploymentFailed:
		return map[string]bool{"item_kind": true}, true
	}
	return nil, false
}

// itemKinds are the deployable kinds a deployment_failed rule may narrow to.
// Compliance is deliberately absent: a failed compliance status is what
// device_non_compliant is for, and having both fire on it would send two
// emails about one machine.
var itemKinds = map[string]bool{"script": true, "app": true, "profile": true, "agent": true}

// ParseParams reads one rule's parameters for its kind.
func ParseParams(kind string, raw []byte) (Params, error) {
	m := map[string]json.RawMessage{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &m); err != nil {
			return Params{}, fmt.Errorf("%w: %v", ErrBadRule, err)
		}
	}
	allowed, known := allowedFields(kind)
	if !known {
		return Params{}, fmt.Errorf("%w: unsupported kind %q", ErrBadRule, kind)
	}
	for field := range m {
		if !allowed[field] {
			return Params{}, fmt.Errorf("%w: field %q does not apply to kind %q", ErrBadRule, field, kind)
		}
	}

	var p Params
	switch kind {
	case store.AlertDeviceNonCompliant:
		if v, ok := m["policy_id"]; ok && string(v) != "null" {
			var s string
			if err := json.Unmarshal(v, &s); err != nil {
				return Params{}, fmt.Errorf("%w: policy_id must be a string", ErrBadRule)
			}
			id, err := uuid.Parse(s)
			if err != nil {
				return Params{}, fmt.Errorf("%w: policy_id must be a UUID", ErrBadRule)
			}
			p.PolicyID = &id
		}
	case store.AlertDeviceStale:
		v, ok := m["hours"]
		if !ok {
			return Params{}, fmt.Errorf("%w: %s needs hours", ErrBadRule, kind)
		}
		if err := json.Unmarshal(v, &p.Hours); err != nil {
			return Params{}, fmt.Errorf("%w: hours must be a whole number", ErrBadRule)
		}
		if p.Hours < 1 || p.Hours > maxStaleHours {
			return Params{}, fmt.Errorf("%w: hours must be between 1 and %d", ErrBadRule, maxStaleHours)
		}
	case store.AlertDeploymentFailed:
		if v, ok := m["item_kind"]; ok && string(v) != "null" {
			if err := json.Unmarshal(v, &p.ItemKind); err != nil {
				return Params{}, fmt.Errorf("%w: item_kind must be a string", ErrBadRule)
			}
			if p.ItemKind != "" && !itemKinds[p.ItemKind] {
				return Params{}, fmt.Errorf("%w: unsupported item_kind %q", ErrBadRule, p.ItemKind)
			}
		}
	}
	return p, nil
}

// Describe renders a rule's kind and parameters as the sentence the console
// and the alert message both show, so the two never disagree about what a
// rule means.
func Describe(kind string, p Params) string {
	switch kind {
	case store.AlertDeviceNonCompliant:
		if p.PolicyID != nil {
			return "a device is non-compliant with one policy"
		}
		return "a device is non-compliant with any policy"
	case store.AlertDeviceStale:
		if p.Hours == 1 {
			return "a device has not checked in for an hour"
		}
		return fmt.Sprintf("a device has not checked in for %d hours", p.Hours)
	case store.AlertDeploymentFailed:
		if p.ItemKind != "" {
			return "a " + p.ItemKind + " deployment failed on a device"
		}
		return "a deployment failed on a device"
	}
	return kind
}

// firing asks the database what a rule is firing about right now. Each kind is
// one query over rows the server already maintains: alerting adds a schedule
// and a delivery, not a second source of truth about the fleet.
func firing(ctx context.Context, q *store.Queries, kind string, p Params, now time.Time) ([]store.AlertSubject, error) {
	switch kind {
	case store.AlertDeviceNonCompliant:
		return q.FiringNonCompliantDevices(ctx, p.PolicyID)
	case store.AlertDeviceStale:
		return q.FiringStaleDevices(ctx, now.Add(-time.Duration(p.Hours)*time.Hour))
	case store.AlertDeploymentFailed:
		return q.FiringFailedDeployments(ctx, p.ItemKind)
	}
	return nil, fmt.Errorf("%w: unsupported kind %q", ErrBadRule, kind)
}

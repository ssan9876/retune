package adminapi

import (
	"net/http"
	"sort"
	"time"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

type dashboardDevicesJSON struct {
	Active  int `json:"active"`
	Stale   int `json:"stale"`
	Retired int `json:"retired"`
	Total   int `json:"total"`
}

type dashboardComplianceJSON struct {
	Compliant    int `json:"compliant"`
	NonCompliant int `json:"non_compliant"`
	Unknown      int `json:"unknown"`
	NotEvaluated int `json:"not_evaluated"`
}

type dashboardFailedDeploymentsJSON struct {
	Script  int `json:"script"`
	App     int `json:"app"`
	Profile int `json:"profile"`
	Agent   int `json:"agent"`
}

type agentVersionCountJSON struct {
	Version string `json:"version"`
	Count   int    `json:"count"`
}

type osBuildCountJSON struct {
	Build string `json:"build"`
	Count int    `json:"count"`
}

// dayCountJSON is one column of the enrolment trend. The day is a plain date
// rather than a timestamp: it is a bucket, not an instant, and rendering it in
// the browser's zone would slide a bar into the wrong day.
type dayCountJSON struct {
	Day   string `json:"day"`
	Count int    `json:"count"`
}

type checkinRecencyJSON struct {
	Hour  int `json:"hour"`
	Day   int `json:"day"`
	Week  int `json:"week"`
	Older int `json:"older"`
	Never int `json:"never"`
}

type dashboardJSON struct {
	Devices           dashboardDevicesJSON           `json:"devices"`
	Compliance        dashboardComplianceJSON        `json:"compliance"`
	FailedDeployments dashboardFailedDeploymentsJSON `json:"failed_deployments"`
	CheckinRecency    checkinRecencyJSON             `json:"checkin_recency"`
	EnrollmentTrend   []dayCountJSON                 `json:"enrollment_trend"`
	AgentVersions     []agentVersionCountJSON        `json:"agent_versions"`
	OSBuilds          []osBuildCountJSON             `json:"os_builds"`
}

// enrollmentTrendDays is how far back the dashboard's trend reaches: long
// enough to show a rollout, short enough to stay readable as bars.
const enrollmentTrendDays = 30

// dashboard reports fleet-wide numbers for the console's overview page (spec
// §5). Its device buckets are exactly FleetBar's (web/src/pages/Devices.tsx),
// computed in SQL over the whole fleet rather than the browser's capped
// /devices?limit=200 or - just as bad at scale - pulling every device's row
// into Go: mutually exclusive by construction, since every device falls into
// exactly one of "not active" (retired), "active and stale" or "active and
// not stale". Compliance, failed-deployment and inventory counts are all for
// active devices only, matching ComplianceCounts.
func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Same cutoff newDeviceJSON's Stale flag uses (now - StaleAfter), so the
	// dashboard and the device list's FleetBar never disagree about one device.
	active, stale, retired, err := h.Store.Q().DeviceBucketCounts(ctx, h.Now().Add(-StaleAfter))
	if err != nil {
		h.internal(w, "device bucket counts", err)
		return
	}
	devices := dashboardDevicesJSON{Active: active, Stale: stale, Retired: retired, Total: active + stale + retired}

	agentVersions, err := h.Store.Q().ActiveAgentVersionCounts(ctx)
	if err != nil {
		h.internal(w, "active agent version counts", err)
		return
	}
	osBuilds, err := h.Store.Q().ActiveOSBuildCounts(ctx)
	if err != nil {
		h.internal(w, "active os build counts", err)
		return
	}

	complianceCounts, err := h.Store.Q().ComplianceCounts(ctx)
	if err != nil {
		h.internal(w, "compliance counts", err)
		return
	}
	failed, err := h.Store.Q().FailedDeploymentCounts(ctx)
	if err != nil {
		h.internal(w, "failed deployment counts", err)
		return
	}
	now := h.Now()
	hour, day, week, older, never, err := h.Store.Q().CheckInRecency(ctx, now)
	if err != nil {
		h.internal(w, "check-in recency", err)
		return
	}
	trend, err := h.Store.Q().EnrollmentTrend(ctx, now.AddDate(0, 0, -(enrollmentTrendDays-1)))
	if err != nil {
		h.internal(w, "enrollment trend", err)
		return
	}
	days := make([]dayCountJSON, 0, len(trend))
	for _, d := range trend {
		days = append(days, dayCountJSON{Day: d.Day.Format(time.DateOnly), Count: d.Count})
	}

	writeJSON(w, http.StatusOK, dashboardJSON{
		Devices: devices,
		Compliance: dashboardComplianceJSON{
			Compliant:    complianceCounts[store.ComplianceCompliant],
			NonCompliant: complianceCounts[store.ComplianceNonCompliant],
			Unknown:      complianceCounts[store.ComplianceUnknown],
			NotEvaluated: complianceCounts[store.ComplianceNotEvaluated],
		},
		FailedDeployments: dashboardFailedDeploymentsJSON{
			Script:  failed[protocol.ItemKindScript],
			App:     failed[protocol.ItemKindApp],
			Profile: failed[protocol.ItemKindProfile],
			Agent:   failed[protocol.ItemKindAgent],
		},
		CheckinRecency:  checkinRecencyJSON{Hour: hour, Day: day, Week: week, Older: older, Never: never},
		EnrollmentTrend: days,
		AgentVersions: topCounts(agentVersions, 10, func(version string, count int) agentVersionCountJSON {
			return agentVersionCountJSON{Version: version, Count: count}
		}),
		OSBuilds: topCounts(osBuilds, 10, func(build string, count int) osBuildCountJSON {
			return osBuildCountJSON{Build: build, Count: count}
		}),
	})
}

// topCounts returns the n highest counts from a key->count map, highest
// first and ties broken by key so the result is deterministic rather than
// dependent on Go's randomized map order.
func topCounts[T any](counts map[string]int, n int, newItem func(key string, count int) T) []T {
	type entry struct {
		key   string
		count int
	}
	entries := make([]entry, 0, len(counts))
	for k, c := range counts {
		entries = append(entries, entry{k, c})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count != entries[j].count {
			return entries[i].count > entries[j].count
		}
		return entries[i].key < entries[j].key
	})
	if len(entries) > n {
		entries = entries[:n]
	}
	out := make([]T, 0, len(entries))
	for _, e := range entries {
		out = append(out, newItem(e.key, e.count))
	}
	return out
}

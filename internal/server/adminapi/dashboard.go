package adminapi

import (
	"net/http"
	"sort"

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

type dashboardJSON struct {
	Devices           dashboardDevicesJSON           `json:"devices"`
	Compliance        dashboardComplianceJSON        `json:"compliance"`
	FailedDeployments dashboardFailedDeploymentsJSON `json:"failed_deployments"`
	AgentVersions     []agentVersionCountJSON        `json:"agent_versions"`
	OSBuilds          []osBuildCountJSON             `json:"os_builds"`
}

// dashboard reports fleet-wide numbers for the console's overview page (spec
// §5). Its device buckets are exactly FleetBar's (web/src/pages/Devices.tsx),
// computed here over the whole fleet rather than the browser's capped
// /devices?limit=200: mutually exclusive by construction, since every device
// falls into exactly one of "not active" (retired), "active and stale" or
// "active and not stale". Compliance, failed-deployment and inventory counts
// are all for active devices only, matching ComplianceCounts.
func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := h.Store.Q().ListDevices(ctx)
	if err != nil {
		h.internal(w, "list devices", err)
		return
	}

	var devices dashboardDevicesJSON
	agentVersions := map[string]int{}
	osBuilds := map[string]int{}
	for _, d := range rows {
		devices.Total++
		if d.Status != store.DeviceActive {
			devices.Retired++
			continue
		}
		// Same definition newDeviceJSON uses for its own Stale flag, so this
		// and the device list's FleetBar never disagree about one device.
		stale := d.LastSeenAt == nil || h.Now().Sub(*d.LastSeenAt) > staleAfter
		if stale {
			devices.Stale++
		} else {
			devices.Active++
		}
		if d.AgentVersion != "" {
			agentVersions[d.AgentVersion]++
		}
		if d.OSBuild != "" {
			osBuilds[d.OSBuild]++
		}
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

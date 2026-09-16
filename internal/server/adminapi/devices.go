package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/devices"
	"retune/internal/server/store"
)

// staleAfter is how long a device may go unseen before the console flags it.
const staleAfter = 7 * 24 * time.Hour

type deviceJSON struct {
	ID            string     `json:"id"`
	Hostname      string     `json:"hostname"`
	Status        string     `json:"status"`
	OSVersion     string     `json:"os_version"`
	OSBuild       string     `json:"os_build"`
	Manufacturer  string     `json:"manufacturer"`
	Model         string     `json:"model"`
	Serial        string     `json:"serial"`
	SMBIOSUUID    string     `json:"smbios_uuid"`
	AgentVersion  string     `json:"agent_version"`
	EnrolledAt    time.Time  `json:"enrolled_at"`
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`
	CertExpiresAt time.Time  `json:"cert_expires_at"`
	Stale         bool       `json:"stale"`
	// Compliance is the device's overall compliance state (design §2); it is
	// filled in by listDevices/getDevice from a batch ComplianceOverall call,
	// not by newDeviceJSON itself, since other callers of newDeviceJSON (group
	// membership, rule preview) have no need to pay for that query.
	Compliance string `json:"compliance"`
}

func (h *Handler) newDeviceJSON(d store.Device) deviceJSON {
	stale := d.LastSeenAt == nil || h.Now().Sub(*d.LastSeenAt) > staleAfter
	return deviceJSON{
		ID: d.ID.String(), Hostname: d.Hostname, Status: d.Status,
		OSVersion: d.OSVersion, OSBuild: d.OSBuild, Manufacturer: d.Manufacturer, Model: d.Model,
		Serial: d.Serial, SMBIOSUUID: d.SMBIOSUUID, AgentVersion: d.AgentVersion,
		EnrolledAt: d.EnrolledAt, LastSeenAt: d.LastSeenAt, CertExpiresAt: d.CertExpiresAt,
		Stale: stale && d.Status == store.DeviceActive,
	}
}

type softwareJSON struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher"`
	InstallDate string `json:"install_date"`
	Scope       string `json:"scope"`
}

type inventoryJSON struct {
	CollectedAt time.Time       `json:"collected_at"`
	ReceivedAt  time.Time       `json:"received_at"`
	RAMGB       float64         `json:"ram_gb"`
	DiskFreeGB  float64         `json:"disk_free_gb"`
	Document    json.RawMessage `json:"document"`
}

type deviceDetailJSON struct {
	Device    deviceJSON     `json:"device"`
	Inventory *inventoryJSON `json:"inventory"`
	Software  []softwareJSON `json:"software"`
	Commands  []commandJSON  `json:"commands"`
}

func (h *Handler) listDevices(w http.ResponseWriter, r *http.Request) {
	page := pageFrom(r)
	q := r.URL.Query()
	rows, total, err := h.Store.Q().ListDevicesPage(r.Context(), store.DeviceFilter{
		Search: q.Get("search"), Status: q.Get("status"), Page: page,
	})
	if err != nil {
		h.internal(w, "list devices", err)
		return
	}
	ids := make([]uuid.UUID, len(rows))
	for i, d := range rows {
		ids[i] = d.ID
	}
	overall, err := h.Store.Q().ComplianceOverall(r.Context(), ids)
	if err != nil {
		h.internal(w, "compliance overall", err)
		return
	}
	items := make([]deviceJSON, 0, len(rows))
	for _, d := range rows {
		item := h.newDeviceJSON(d)
		item.Compliance = overall[d.ID]
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, newListResponse(items, total, page))
}

func (h *Handler) getDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such device")
	if !ok {
		return
	}
	ctx := r.Context()
	q := h.Store.Q()
	d, err := q.GetDevice(ctx, store.DefaultTenantID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such device")
		return
	}
	if err != nil {
		h.internal(w, "get device", err)
		return
	}
	detail := deviceDetailJSON{Device: h.newDeviceJSON(d), Software: []softwareJSON{}, Commands: []commandJSON{}}
	overall, err := q.ComplianceOverall(ctx, []uuid.UUID{id})
	if err != nil {
		h.internal(w, "compliance overall", err)
		return
	}
	detail.Device.Compliance = overall[id]

	inv, err := q.GetInventory(ctx, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		h.internal(w, "get inventory", err)
		return
	default:
		detail.Inventory = &inventoryJSON{
			CollectedAt: inv.CollectedAt, ReceivedAt: inv.ReceivedAt,
			RAMGB: inv.RAMGB, DiskFreeGB: inv.DiskFreeGB, Document: json.RawMessage(inv.Data),
		}
	}

	sw, err := q.ListSoftware(ctx, id)
	if err != nil {
		h.internal(w, "list software", err)
		return
	}
	for _, s := range sw {
		detail.Software = append(detail.Software, softwareJSON(s))
	}

	cmds, err := q.ListCommands(ctx, id, 20)
	if err != nil {
		h.internal(w, "list commands", err)
		return
	}
	for _, c := range cmds {
		detail.Commands = append(detail.Commands, newCommandJSON(c))
	}
	writeJSON(w, http.StatusOK, detail)
}

func (h *Handler) listDeviceSoftware(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such device")
	if !ok {
		return
	}
	sw, err := h.Store.Q().ListSoftware(r.Context(), id)
	if err != nil {
		h.internal(w, "list software", err)
		return
	}
	items := make([]softwareJSON, 0, len(sw))
	for _, s := range sw {
		items = append(items, softwareJSON(s))
	}
	writeJSON(w, http.StatusOK, newListResponse(items, len(items), store.Page{Limit: len(items)}))
}

func (h *Handler) retireDevice(w http.ResponseWriter, r *http.Request) {
	h.changeDeviceStatus(w, r, false)
}

func (h *Handler) unenrollDevice(w http.ResponseWriter, r *http.Request) {
	h.changeDeviceStatus(w, r, true)
}

func (h *Handler) changeDeviceStatus(w http.ResponseWriter, r *http.Request, unenroll bool) {
	id, ok := pathUUID(w, r, "no such device")
	if !ok {
		return
	}
	actor := caller(r).Admin.Email
	var err error
	if unenroll {
		err = h.Devices.Unenroll(r.Context(), id, actor)
	} else {
		err = h.Devices.Retire(r.Context(), id, actor)
	}
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, devices.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such device")
	case errors.Is(err, devices.ErrInvalidTransition):
		writeError(w, http.StatusConflict, "invalid_transition", err.Error())
	default:
		h.internal(w, "change device status", err, "device_id", id)
	}
}

// pathUUID reads the {id} path value.
func pathUUID(w http.ResponseWriter, r *http.Request, message string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", message)
		return uuid.UUID{}, false
	}
	return id, true
}

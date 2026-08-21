package avsettings

// The settings screen.
//
// The response carries FOUR views of the same limits and that is deliberate:
//
//	settings   what the operator wrote, where 0 may mean automatic
//	capacity   what this server actually has, and what the panel suggests
//	effective  what those settings resolve to once automatic is resolved
//	kernel     what systemd reports it is enforcing right now
//
// Showing only the first turns "I set 200%" into a belief with nothing behind
// it. The last one is the only view that is evidence, and it is read from
// systemd rather than from the row that was just written.

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"servika/internal/httpx"
)

type Handlers struct{ DB *sql.DB }

// Response is the settings screen's whole state.
type Response struct {
	Settings  Settings     `json:"settings"`
	Capacity  Capacity     `json:"capacity"`
	Effective Effective    `json:"effective"`
	Kernel    KernelLimits `json:"kernel"`
	ScanRoots []string     `json:"scan_roots"`
}

// Get answers GET /admin/antivirus/settings.
func (h *Handlers) Get(w http.ResponseWriter, r *http.Request) {
	settings, err := Read(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the antivirus settings could not be read")
		return
	}
	h.respond(w, settings)
}

// Put answers PUT /admin/antivirus/settings.
//
// It answers with the same body Get would, read back AFTER the write, so the
// screen shows what the server is doing rather than what was asked for. The two
// differ whenever the kernel refused a limit, which is the case this whole
// screen exists to make visible.
func (h *Handlers) Put(w http.ResponseWriter, r *http.Request) {
	var settings Settings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "the request body could not be read")
		return
	}
	if err := Write(r.Context(), h.DB, settings); err != nil {
		// A refused FIELD is the operator's input and carries a stable code the
		// screen words in twelve languages. Anything else is the server failing
		// and must not be presented as a field they typed wrong.
		if code := ReasonCode(err); code != "" {
			httpx.WriteJSON(w, http.StatusBadRequest,
				map[string]string{"error": err.Error(), "reason": code})
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError,
			"the antivirus settings could not be saved: "+err.Error())
		return
	}
	stored, err := Read(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the antivirus settings could not be read back")
		return
	}
	h.respond(w, stored)
}

func (h *Handlers) respond(w http.ResponseWriter, settings Settings) {
	capacity := ServerCapacity()
	httpx.WriteJSON(w, http.StatusOK, Response{
		Settings:  settings,
		Capacity:  capacity,
		Effective: settings.Resolve(capacity),
		Kernel:    ReadKernelLimits(),
		ScanRoots: settings.ScanRoots(),
	})
}

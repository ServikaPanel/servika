package laravel

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

// workerRequest is the body every write takes. It is the same shape for create
// and update so the screen has one form.
type workerRequest struct {
	Name       string `json:"name"`
	Connection string `json:"connection"`
	Queues     string `json:"queues"`
	Processes  int    `json:"processes"`
	Tries      int    `json:"tries"`
	Timeout    int    `json:"timeout_sec"`
	Sleep      int    `json:"sleep_sec"`
	MaxJobs    int    `json:"max_jobs"`
	MemoryMB   int    `json:"memory_mb"`
	Enabled    bool   `json:"enabled"`
}

func writeWorkerReason(w http.ResponseWriter, status int, message, reason string) {
	httpx.WriteJSON(w, status, map[string]string{"error": message, "reason": reason})
}

// workerView is one definition plus what systemd says about it.
type workerView struct {
	Worker
	Status WorkerStatus `json:"status"`
}

// WorkerList answers with every definition on the domain and its live state.
func (h *Handlers) WorkerList(w http.ResponseWriter, r *http.Request) {
	id, _, _, _, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	workers, err := WorkersForDomain(r.Context(), h.DB, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the workers could not be read")
		return
	}
	views := make([]workerView, 0, len(workers))
	for _, worker := range workers {
		views = append(views, workerView{Worker: worker, Status: ReadWorkerStatus(worker)})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"workers": views, "max_processes": maxWorkerProcesses})
}

// WorkerCreate stores a new definition and applies it.
func (h *Handlers) WorkerCreate(w http.ResponseWriter, r *http.Request) {
	id, systemUser, phpVersion, demo, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "queue workers cannot be managed for demo subscriptions")
		return
	}
	worker, bad := decodeWorker(r, id, 0)
	if bad != "" {
		writeWorkerReason(w, http.StatusBadRequest, "the worker definition is not usable", bad)
		return
	}
	defer lockDomain(id)()

	stored, err := InsertWorker(r.Context(), h.DB, worker)
	if err != nil {
		if isDuplicateName(err) {
			writeWorkerReason(w, http.StatusConflict, "a worker with that name already exists", reasonWorkerDuplicate)
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "the worker could not be stored")
		return
	}
	h.applyAndAnswer(w, r, stored, id, systemUser, phpVersion)
}

// WorkerUpdate writes a definition back and re-applies it.
func (h *Handlers) WorkerUpdate(w http.ResponseWriter, r *http.Request) {
	id, systemUser, phpVersion, demo, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "queue workers cannot be managed for demo subscriptions")
		return
	}
	existing, found := h.worker(r, id)
	if !found {
		writeWorkerReason(w, http.StatusNotFound, "that worker does not belong to this domain", reasonWorkerUnknown)
		return
	}
	worker, bad := decodeWorker(r, id, existing.ID)
	if bad != "" {
		writeWorkerReason(w, http.StatusBadRequest, "the worker definition is not usable", bad)
		return
	}
	defer lockDomain(id)()

	if err := UpdateWorker(r.Context(), h.DB, worker); err != nil {
		if isDuplicateName(err) {
			writeWorkerReason(w, http.StatusConflict, "a worker with that name already exists", reasonWorkerDuplicate)
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "the worker could not be stored")
		return
	}
	h.applyAndAnswer(w, r, worker, id, systemUser, phpVersion)
}

// WorkerDelete removes a definition and everything it put on the host.
func (h *Handlers) WorkerDelete(w http.ResponseWriter, r *http.Request) {
	id, _, _, _, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	worker, found := h.worker(r, id)
	if !found {
		writeWorkerReason(w, http.StatusNotFound, "that worker does not belong to this domain", reasonWorkerUnknown)
		return
	}
	defer lockDomain(id)()

	// The host comes down first. A row deleted while its units still run leaves
	// processes nothing in the panel can name, let alone stop.
	TeardownWorker(worker.ID)
	if err := DeleteWorker(r.Context(), h.DB, id, worker.ID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the worker was stopped but its record remains")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// WorkerRestart restarts a worker in place, which is how a customer picks up
// code they changed outside a deploy.
func (h *Handlers) WorkerRestart(w http.ResponseWriter, r *http.Request) {
	id, _, _, demo, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "queue workers cannot be managed for demo subscriptions")
		return
	}
	worker, found := h.worker(r, id)
	if !found {
		writeWorkerReason(w, http.StatusNotFound, "that worker does not belong to this domain", reasonWorkerUnknown)
		return
	}
	if err := RestartWorker(worker); err != nil {
		writeWorkerReason(w, http.StatusInternalServerError, "the worker did not restart", reasonWorkerApplyFail)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "status": ReadWorkerStatus(worker)})
}

// WorkerLog returns the tail of one worker's output.
func (h *Handlers) WorkerLog(w http.ResponseWriter, r *http.Request) {
	id, _, _, _, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	worker, found := h.worker(r, id)
	if !found {
		writeWorkerReason(w, http.StatusNotFound, "that worker does not belong to this domain", reasonWorkerUnknown)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"log": WorkerLogTail(worker.ID)})
}

// worker reads the {wid} worker, narrowed to the domain in the URL.
func (h *Handlers) worker(r *http.Request, domainID int64) (Worker, bool) {
	workerID, err := strconv.ParseInt(chi.URLParam(r, "wid"), 10, 64)
	if err != nil {
		return Worker{}, false
	}
	worker, err := GetWorker(r.Context(), h.DB, domainID, workerID)
	if err != nil {
		return Worker{}, false
	}
	return worker, true
}

// decodeWorker reads and validates a request body into a definition.
func decodeWorker(r *http.Request, domainID, workerID int64) (Worker, string) {
	var req workerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return Worker{}, reasonWorkerName
	}
	worker := Worker{
		ID:         workerID,
		DomainID:   domainID,
		Name:       req.Name,
		Connection: req.Connection,
		Queues:     req.Queues,
		Processes:  req.Processes,
		Tries:      req.Tries,
		Timeout:    req.Timeout,
		Sleep:      req.Sleep,
		MaxJobs:    req.MaxJobs,
		MemoryMB:   req.MemoryMB,
		Enabled:    req.Enabled,
	}
	if bad := ValidateWorker(&worker); bad != "" {
		return Worker{}, bad
	}
	return worker, ""
}

// applyAndAnswer puts a stored definition on the host and reports what systemd
// says about it right now.
//
// It does NOT wait to see whether the worker settles. The only true statement
// after an enable is that the worker STARTED; whether it stays up belongs to the
// list endpoint the page polls.
func (h *Handlers) applyAndAnswer(w http.ResponseWriter, r *http.Request, worker Worker,
	domainID int64, systemUser, phpVersion string) {
	appDir, err := h.appDir(r, domainID, systemUser)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid application directory")
		return
	}
	if err := ApplyWorker(worker, domainID, systemUser, appDir, phpBin(phpVersion)); err != nil {
		writeWorkerReason(w, http.StatusInternalServerError,
			"the definition was saved but the worker did not start", reasonWorkerApplyFail)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, workerView{Worker: worker, Status: ReadWorkerStatus(worker)})
}

// isDuplicateName reports whether an error is the unique-name key firing.
//
// The key is named explicitly rather than matched on the driver's duplicate
// error number alone: the table carries a primary key too, and answering 409
// for that one would blame the customer for something they cannot fix.
func isDuplicateName(err error) bool {
	return err != nil && strings.Contains(err.Error(), "uk_laravel_worker_name")
}

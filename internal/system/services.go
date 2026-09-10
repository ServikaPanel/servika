package system

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"

	"servika/internal/httpx"
)

type serviceDefinition struct {
	Unit       string `json:"unit"`
	Label      string `json:"label"`
	Group      string `json:"group"`
	Reloadable bool   `json:"reloadable"`
}

type serviceStatus struct {
	serviceDefinition
	Status string `json:"status"`
}

var serviceAllowlist = []serviceDefinition{
	{Unit: "nginx", Label: "Nginx", Group: "Web Server", Reloadable: true},
	{Unit: "httpd", Label: "Apache (Backend)", Group: "Web Server", Reloadable: true},
	{Unit: "mariadb", Label: "MariaDB", Group: "Database & Cache"},
	{Unit: "valkey", Label: "Valkey (Redis)", Group: "Database & Cache"},
	{Unit: "named", Label: "BIND", Group: "DNS", Reloadable: true},
	{Unit: "php-fpm", Label: "PHP-FPM 8.3", Group: "PHP-FPM", Reloadable: true},
	{Unit: "php82-php-fpm", Label: "PHP-FPM 8.2", Group: "PHP-FPM", Reloadable: true},
	{Unit: "php74-php-fpm", Label: "PHP-FPM 7.4", Group: "PHP-FPM", Reloadable: true},
	// The mail stack an administrator may turn off entirely once the last mail
	// customer leaves. Without these rows its state was invisible here, and a
	// domain whose mail had simply stopped looked healthy.
	{Unit: "postfix", Label: "Postfix (SMTP)", Group: "Mail", Reloadable: true},
	{Unit: "dovecot", Label: "Dovecot (IMAP/POP)", Group: "Mail", Reloadable: true},
	{Unit: "pure-ftpd", Label: "Pure-FTPd (FTP)", Group: "Other"},
	{Unit: "crond", Label: "Cron (Scheduler)", Group: "Other"},
}

var runSystemctl = func(args ...string) string {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	output, _ := exec.Command("systemctl", args...).CombinedOutput()
	return string(output)
}

func findService(unit string) (serviceDefinition, bool) {
	for _, service := range serviceAllowlist {
		if service.Unit == unit {
			return service, true
		}
	}
	return serviceDefinition{}, false
}

func serviceState(unit string) string {
	status := strings.TrimSpace(runSystemctl("is-active", unit))
	if status == "" || status == "unknown" {
		return "absent"
	}
	return status
}

// ServiceStatuses returns the state of each allowlisted systemd service.
func ServiceStatuses(w http.ResponseWriter, _ *http.Request) {
	statuses := make([]serviceStatus, 0, len(serviceAllowlist))
	for _, service := range serviceAllowlist {
		statuses = append(statuses, serviceStatus{
			serviceDefinition: service,
			Status:            serviceState(service.Unit),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, statuses)
}

// ServiceAction restarts or reloads an allowlisted systemd service.
func ServiceAction(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Unit   string `json:"unit"`
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	service, allowed := findService(request.Unit)
	if !allowed {
		httpx.WriteError(w, http.StatusForbidden, "service action is not allowed")
		return
	}
	if request.Action != "restart" && request.Action != "reload" {
		httpx.WriteError(w, http.StatusBadRequest, "action must be restart or reload")
		return
	}
	action := request.Action
	if action == "reload" && !service.Reloadable {
		action = "restart"
	}
	runSystemctl(action, service.Unit)
	// The usage endpoint serves its service list from a cache. Drop it here, or
	// the dashboard keeps reporting the state from before this action for the
	// rest of the TTL and the restart reads as having done nothing.
	InvalidateServices()
	status := serviceState(service.Unit)
	if status != "active" {
		httpx.WriteError(w, http.StatusInternalServerError, "service action failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"unit":   service.Unit,
		"action": action,
		"status": status,
	})
}

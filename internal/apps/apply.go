package apps

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
)

// RenderSubdomain rewrites a subdomain's own server block. It is a hook rather
// than a direct call because internal/subdomain reads domain records and so
// imports internal/domains, which in turn tears down applications: calling it
// from here would close that ring into an import cycle. `main` wires it to
// subdomain.ReRender.
var RenderSubdomain func(db *sql.DB, subdomainID int64) error

// apply publishes an application to the host: its environment file, its unit,
// its systemd state and the vhost that proxies to it.
//
// Every step reports its own failure. A half-applied application is worse than
// a failed create, so the caller rolls back rather than reporting success.
func (h *Handlers) apply(r *http.Request, s scope, app App, appDir string, argv []string) error {
	values, err := ReadEnv(r.Context(), h.DB, app.ID)
	if err != nil {
		return fmt.Errorf("read the environment: %w", err)
	}
	if err := WriteEnvFile(app, values); err != nil {
		return err
	}
	if err := EnsureLogFile(app.ID); err != nil {
		return err
	}
	execStart, err := ResolveExec(app.Runtime, app.Version, appDir, argv)
	if err != nil {
		return err
	}
	if err := InstallUnit(app.ID, RenderUnit(app, s.SystemUser, appDir, execStart)); err != nil {
		return err
	}
	if app.Enabled {
		if err := Enable(app.ID); err != nil {
			return err
		}
	} else if err := Disable(app.ID); err != nil {
		return err
	}
	return h.render(s, app.SubdomainID)
}

// render rewrites the nginx configuration that carries the application's proxy
// block: the subdomain's own server block, or the parent domain's.
func (h *Handlers) render(s scope, subdomainID int64) error {
	if subdomainID > 0 {
		if RenderSubdomain == nil {
			return errors.New("the subdomain renderer is not wired")
		}
		return RenderSubdomain(h.DB, subdomainID)
	}
	socket, err := phpSocketFor(s.SystemUser, s.PHPVersion)
	if err != nil {
		return fmt.Errorf("resolve the PHP socket: %w", err)
	}
	return applyVhostForDomain(h.DB, s.DomainID, socket, s.PHPVersion)
}

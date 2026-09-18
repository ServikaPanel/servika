//go:build windows

package main

// The local panel's interface, embedded in the binary.
//
// The agent is ONE file an operator copies to a Windows host. A separate assets
// directory would mean the panel is blank the moment somebody copies the exe
// alone, so the whole interface (four files, no outside request, no CDN) is
// compiled in with go:embed.

import (
	"embed"
	"io/fs"
	"net/http"

	"servika/internal/logx"
)

//go:embed webui
var webFiles embed.FS

// mountInterface serves the interface at the root.
//
// A failure here is NOT fatal: the agent API on 8460 and every /api/local
// endpoint keep working, and the operator sees a plain message at the root
// instead of a panel that half loads.
func mountInterface(mux *http.ServeMux) {
	sub, err := fs.Sub(webFiles, "webui")
	if err != nil {
		logx.Warnf("the local panel's interface could not be mounted: %v", err)
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("the interface could not be mounted; the API is still up\n"))
		})
		return
	}
	mux.Handle("/", staticHandler(sub))
}

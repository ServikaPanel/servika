//go:build windows

package main

// Mounting the local panel's interface.
//
// The interface itself is embedded in its own file, so this one holds only the
// rule that the root serves it. Until the interface is bundled, the root says
// so plainly rather than answering 404, which would read as a broken agent.

import "net/http"

// mountInterface puts the interface, or an honest placeholder, at the root.
func mountInterface(mux *http.ServeMux) {
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		writeStaticHeaders(w)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("The Servika agent is running. The browser interface is not bundled into this build; the API under /api/local is available.\n"))
	}))
}

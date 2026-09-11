package antivirus

import "servika/internal/db"

// The host, the scan and the watcher startup a handler reaches. Each is a
// variable whose default is the call this package made before, so a test can
// drive a handler without root, a tenant tree or a real sweep of the server.

// tenantHomeBase is the directory every tenant home sits under.
var tenantHomeBase = "/home/"

// scanTree runs one scan, in the resource slice where systemd is present. Both
// the per-domain handler and the sweep start their scan through it.
var scanTree = Scan

// containInHome copies a finding's file out of the tenant home into the store
// and removes the original.
var containInHome = contain

// The real-time watcher's startup: its database, the signed rule package, the
// watcher itself and its event loop.
var (
	openWatchDB       = db.Open
	loadPackagedRules = LoadRulesFromDisk
	startWatcher      = newWatcher
	watchFiles        = (*watcher).run
)

package antivirus

// Who started a scan.
//
// av_scans.scope already says WHAT was scanned. It cannot say who asked for it,
// so a sweep an operator ran by hand and one the scheduler ran overnight were
// drawn identically, and the only way to see that the nightly job really ran was
// to compare timestamps by eye.
//
// The values live here rather than as five literals at five insert sites,
// because a sixth spelling at a sixth site is a value the screen has no word for
// and nothing would report the drift.
const (
	// SourceManual is a person: the domain scan button or the sweep button.
	SourceManual = "manual"
	// SourceScheduled is the panel's own in-process scheduler.
	SourceScheduled = "scheduled"
	// SourceTimer is the systemd timer running `servika-server -av-sweep`, which
	// still sweeps while the panel is down.
	SourceTimer = "timer"
	// SourceRealtime is the fanotify watcher: nobody asked, a file was written.
	SourceRealtime = "realtime"
	// SourceUnknown is the column default and belongs to rows written before the
	// column existed. Nothing writes it; "not measured" is a different claim from
	// "started by hand".
	SourceUnknown = "unknown"
)

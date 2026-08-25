package antivirus

// Which detector produced a finding, and what that means for what can be done
// about it.
//
// Every finding used to describe a FILE, and three separate places relied on
// that without saying so: the automatic containment query, the containment
// handler and the two screens that draw a Contain button. A detector whose
// subject is not a file therefore has to be recognisable, and the engine name
// is what recognises it, because it is already the column the screen groups by
// and the value each detector owns.

// EngineDatabase is the WordPress database scan. Its subject is a row in a
// tenant's own MariaDB schema, so its `file` column names a table and a row id
// rather than a path.
const EngineDatabase = "database"

// Containable reports whether a finding from this engine describes something
// the quarantine can act on.
//
// Containment is a copy out of the tenant home followed by a removal. A finding
// with no file has no subject for either, so the answer is not "it failed" but
// "there was never anything to do". That distinction is the whole point: a
// refusal counted as a failure sends an operator after a fault that is not
// there, which is the same rule `auto_quarantine_core_skipped` exists for.
//
// The test is on the engine rather than on the shape of the path. Guessing from
// the text would make the answer depend on what a detector happened to write,
// and a path is exactly what an attacker controls in the file case.
func Containable(engine string) bool {
	return engine != EngineDatabase
}

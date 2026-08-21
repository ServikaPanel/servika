// Package phpdefaults holds the per-domain PHP limits a domain receives when it
// has no php_settings row of its own.
//
// These five values used to be written out in four separate places: the column
// DEFAULT clauses in the migrations, php.Defaults() (what the panel SHOWS), the
// tenant pool renderer in internal/provisioner (what PHP actually RUNS), and the
// performance summary. Raising three of the four left the panel reporting one
// limit while the interpreter enforced another, with nothing in the code saying
// which was right.
//
// internal/php imports internal/provisioner, so provisioner cannot call
// php.Defaults(); this package imports nothing at all, so both sides can read
// it. TestTheMigrationsAgreeWithTheseConstants pins the remaining pair, the SQL
// column defaults and these constants, so the two can no longer drift.
package phpdefaults

const (
	// MemoryLimit is php_admin_value[memory_limit].
	MemoryLimit = "2048M"
	// MaxExecutionTime is php_admin_value[max_execution_time], in seconds.
	MaxExecutionTime = 3000
	// MaxInputTime is php_admin_value[max_input_time], in seconds.
	MaxInputTime = 6000
	// PostMaxSize is php_admin_value[post_max_size].
	PostMaxSize = "8000M"
	// UploadMaxFilesize is php_admin_value[upload_max_filesize].
	UploadMaxFilesize = "2000M"
)

package mtasts

// Both record writers end in a zone write, which reaches named on the host.
// They are variables so a test can run the publication sequence and read what
// it asked for.
var (
	writeEnableRecords = WriteEnableRecords
	writePolicyTXT     = WritePolicyTXT
	removeRecords      = RemoveRecords
)

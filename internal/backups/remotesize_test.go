package backups

import "testing"

// parseRemoteSize reads the byte count out of an lftp `ls` listing without
// depending on a fixed column layout, and returns -1 when it cannot, so the
// caller reads an unparseable listing as "could not verify" rather than a size
// mismatch that would flag a good upload as corrupt.
func TestParseRemoteSizeReadsTheByteCount(t *testing.T) {
	const file = "c_site-20260826-010203.tar.gz"
	cases := []struct {
		name string
		out  string
		want int64
	}{
		{
			name: "sftp long listing",
			out:  "-rw-r--r--    1 1000     1000      1048576 Aug 26 01:02 " + file + "\n",
			want: 1048576,
		},
		{
			name: "ftp listing with a different column order",
			out:  "226-Options: -a -l\n-rw-r--r-- 1 owner group 524288 Aug 26 01:02 " + file + "\n",
			want: 524288,
		},
		{
			name: "no line names the file",
			out:  "-rw-r--r-- 1 o g 999 Aug 26 01:02 other.tar.gz\n",
			want: -1,
		},
		{
			name: "empty output",
			out:  "",
			want: -1,
		},
		{
			name: "the file line carries no numeric field",
			out:  "get: Access failed: " + file + " (No such file)\n",
			want: -1,
		},
	}
	for _, c := range cases {
		if got := parseRemoteSize(c.out, file); got != c.want {
			t.Errorf("%s: parseRemoteSize = %d, want %d", c.name, got, c.want)
		}
	}
}

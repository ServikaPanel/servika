package serverip

import (
	"os"
	"strings"
	"testing"
)

func scanTestdata(t *testing.T, name string) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	bound := map[string]bool{}
	if err := scanListeners(strings.NewReader(string(raw)), bound); err != nil {
		t.Fatalf("scan %s: %v", name, err)
	}
	return bound
}

// /proc/net/tcp writes each 32-bit word of the address in the HOST's byte
// order, so every word is reversed on the platforms this runs on. The fixtures
// are real captures taken with listeners bound to known addresses: 127.0.0.1
// appears as "0100007F" and ::1 as "00000000000000000000000001000000".
//
// Reading them straight rather than reversed gives a valid-looking address that
// is not the one bound, which here means protecting the wrong address and
// permitting the removal of the right one.
func TestTheProcAddressEncodingIsReadTheWayTheKernelWritesIt(t *testing.T) {
	bound := scanTestdata(t, "proc-net-tcp.txt")
	if !bound["127.0.0.1"] {
		t.Errorf("the capture has a listener on 127.0.0.1; parsed %v", bound)
	}
	// 0100007F read straight is 1.0.0.127, which is what a missing reversal
	// produces and must never appear.
	if bound["1.0.0.127"] {
		t.Error("the address was read without reversing the word order")
	}

	bound6 := scanTestdata(t, "proc-net-tcp6.txt")
	if !bound6["::1"] {
		t.Errorf("the capture has a listener on ::1; parsed %v", bound6)
	}
}

// A wildcard bind answers on every address the host has, including ones added
// after it started, so it pins no particular address. Counting it would mark
// every address as bound and refuse every removal, which is why the captures
// deliberately contain one of each.
func TestAWildcardBindPinsNoAddress(t *testing.T) {
	for _, name := range []string{"proc-net-tcp.txt", "proc-net-tcp6.txt"} {
		bound := scanTestdata(t, name)
		for _, wildcard := range []string{"0.0.0.0", "::"} {
			if bound[wildcard] {
				t.Errorf("%s: the wildcard %s was recorded as a bound address", name, wildcard)
			}
		}
		if len(bound) != 1 {
			t.Errorf("%s: %d addresses recorded, the capture has one real listener and one wildcard: %v",
				name, len(bound), bound)
		}
	}
}

// Only a socket in LISTEN (0A) counts. An established connection carries the
// same local address and is not evidence that anything is bound to it.
func TestOnlyAListeningSocketCounts(t *testing.T) {
	// The same row as the capture, in ESTABLISHED (01) rather than LISTEN.
	text := "  sl  local_address rem_address   st\n" +
		"   0: 0100007F:9C3F 0100007F:1234 01 00000000:00000000 00:00000000 00000000\n"
	bound := map[string]bool{}
	if err := scanListeners(strings.NewReader(text), bound); err != nil {
		t.Fatal(err)
	}
	if len(bound) != 0 {
		t.Errorf("an established connection was counted as a bind: %v", bound)
	}
}

// A row this cannot decode is skipped rather than guessed at.
func TestAnUndecodableRowIsSkipped(t *testing.T) {
	text := "  sl  local_address rem_address   st\n" +
		"   0: zzzz:9C3F 00000000:0000 0A x\n" +
		"   1: 0100 00000000:0000 0A x\n" +
		"   2: 0100007F 00000000:0000 0A x\n"
	bound := map[string]bool{}
	if err := scanListeners(strings.NewReader(text), bound); err != nil {
		t.Fatal(err)
	}
	if len(bound) != 0 {
		t.Errorf("a row that could not be decoded produced %v", bound)
	}
}

func TestTheListenPortIsReadFromTheConfiguredAddress(t *testing.T) {
	for value, want := range map[string]int{
		":8080":            8080,
		"127.0.0.1:8080":   8080,
		"[::1]:9090":       9090,
		"0.0.0.0:1":        1,
		"not-an-address":   0,
		"":                 0,
		"127.0.0.1:eighty": 0,
	} {
		if got := ListenPort(value); got != want {
			t.Errorf("ListenPort(%q) = %d, want %d", value, got, want)
		}
	}
}

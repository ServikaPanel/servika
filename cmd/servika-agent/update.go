package main

// The two pieces of the self-update that can be measured without a host: where
// the health check has to be aimed, and what a version line means.

import "strings"

// localHealthURL turns the listen address into the URL the health gate polls.
//
// A wildcard bind is not an address anything can CONNECT to, so it is rewritten
// to loopback. Polling 0.0.0.0 fails on Windows and the gate would read a
// perfectly healthy agent as dead, then roll back a good update.
func localHealthURL(listen string) string {
	address := listen
	for _, wildcard := range []string{"0.0.0.0", "[::]", "::"} {
		if rest, found := strings.CutPrefix(address, wildcard); found && strings.HasPrefix(rest, ":") {
			address = "127.0.0.1" + rest
			break
		}
	}
	return "https://" + address + "/health"
}

// versionField takes the version out of a "<version> <channel>" line.
//
// The health answer carries the version alone, so the channel has to come off
// before they are compared. Comparing the whole line would fail every update.
func versionField(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

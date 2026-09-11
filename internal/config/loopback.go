package config

import (
	"net"
	"strconv"
	"strings"
)

// DefaultBackendPort is where the panel listens when SERVIKA_LISTEN says
// nothing. It matches the default in Load.
const DefaultBackendPort = 8080

// LoopbackBackend returns the host:port a process on THIS machine uses to reach
// the panel's own API directly, bypassing nginx.
//
// The two single sign-on callbacks embedded in generated PHP dialled
// 127.0.0.1:8080 as a literal. Moving the backend port is a shipped feature,
// and its rewrite reaches the two panel vhosts only: neither PHP file was
// enumerated, and both go DIRECT to the backend rather than through nginx, so
// after a port move every "Open phpMyAdmin" and "Open webmail" click failed
// with the token unredeemable. Nothing linked the failure to the port change,
// and the startup heal rewrote any hand repair from its own template on the
// next restart, so the outage was permanent until the port was moved back.
//
// It is derived from SERVIKA_LISTEN, which is where this process is actually
// listening, so a rendered page cannot disagree with the running server.
//
// The HOST is deliberately not taken verbatim. A panel listening on ":8080" or
// "0.0.0.0:8080" is still reached over the loopback from this machine, and a
// wildcard is not an address a client can dial. A specific host is honoured,
// because an operator who bound the panel to one address means it.
func LoopbackBackend() string {
	host, port := "127.0.0.1", DefaultBackendPort
	if listenHost, listenPort, ok := splitListen(envOr("SERVIKA_LISTEN", "")); ok {
		port = listenPort
		if dialableHost(listenHost) {
			host = listenHost
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// splitListen parses a listen value into its host and port.
func splitListen(value string) (host string, port int, ok bool) {
	value = strings.TrimSpace(strings.Trim(strings.TrimSpace(value), `"'`))
	index := strings.LastIndex(value, ":")
	if index < 0 {
		return "", 0, false
	}
	port, err := strconv.Atoi(value[index+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	return value[:index], port, true
}

// dialableHost reports whether a listen host is an address a client on this
// machine can connect to, rather than a wildcard meaning "every interface".
func dialableHost(host string) bool {
	switch strings.TrimSpace(host) {
	case "", "0.0.0.0", "::", "[::]", "*":
		return false
	}
	return true
}

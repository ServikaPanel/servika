package provisioner

import (
	"net"
	"time"
)

// A single resolver hiccup used to be indistinguishable from "this name does
// not exist", and both answers feed decisions that are expensive to get wrong:
// www drops out of the certificate SAN, and the canonical www redirect is then
// refused because the certificate does not name the host it would send visitors
// to. Retry a lookup that FAILED; never retry one that answered, because an
// answer pointing somewhere else is a fact, not a hiccup.
var (
	// resolveHost is a seam so a test can drive this without a resolver.
	resolveHost = net.LookupHost

	resolveAttempts   = 3
	resolveRetryDelay = time.Second
)

// lookupHostRetrying returns the addresses of host, or nil when the resolver
// still has no answer after the retries.
func lookupHostRetrying(host string) []string {
	for attempt := range resolveAttempts {
		if attempt > 0 {
			time.Sleep(resolveRetryDelay)
		}
		addresses, err := resolveHost(host)
		if err == nil && len(addresses) > 0 {
			return addresses
		}
	}
	return nil
}

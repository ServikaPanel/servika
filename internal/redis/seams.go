package redis

// Test seams. Each defaults to the production function, so the behaviour is
// unchanged; a test replaces the one it needs instead of reaching the host.
var (
	// revokeACL removes the tenant's Valkey account through valkey-cli.
	revokeACL = disableUser
	// detachWordPress strips the object-cache drop-in and the WP_REDIS_*
	// constants from every WordPress installation under the tenant's home.
	detachWordPress = disconnectWordPress
)

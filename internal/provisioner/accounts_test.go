package provisioner

import (
	"os/user"
	"testing"
)

// withAccounts answers every Linux account lookup from accounts for one test.
// The test may add or remove entries after the call; the lookup reads the map
// when it runs.
func withAccounts(t *testing.T, accounts map[string]*user.User) {
	t.Helper()
	setForTest(t, &lookupUser, func(name string) (*user.User, error) {
		if account, ok := accounts[name]; ok {
			return account, nil
		}
		return nil, user.UnknownUserError(name)
	})
}

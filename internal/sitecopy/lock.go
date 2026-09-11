package sitecopy

import "sync"

// Creating a staging copy runs `rsync -a` over the tenant's whole document root,
// up to 3 GB, for up to five minutes, as ROOT rather than through runuser. The
// I/O is therefore not charged to the tenant's cgroup, and the handler held no
// lock and no limit: a customer could fire any number of these at once and
// saturate the host's disk for every site and for the panel database.
//
// The space is bounded by the tenant's disk quota, because the copies land in
// their own home. Nothing bounded the I/O or the number of concurrent rsync
// processes, which is what this closes. The handler's own comment already
// records that a root-privileged full-tree scan outside the tenant's cgroup
// limit was recognised as a problem and fixed for the LIST endpoint's size
// measurement; the copy itself was left unbounded.
var copiesInProgress sync.Map // domainID (int64) -> struct{}

// lockDomain claims a domain for one staging copy.
//
// The claim is atomic: LoadOrStore decides and stores in one step, so two
// requests arriving together cannot both win. release is safe to call once,
// through defer, and is nil when the claim failed.
func lockDomain(domainID int64) (release func(), ok bool) {
	if _, loaded := copiesInProgress.LoadOrStore(domainID, struct{}{}); loaded {
		return nil, false
	}
	var once sync.Once
	return func() { once.Do(func() { copiesInProgress.Delete(domainID) }) }, true
}

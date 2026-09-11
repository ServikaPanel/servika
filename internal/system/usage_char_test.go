package system

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

var errNoReading = errors.New("no reading for this mount")

// mountsFile points the disk reading at a fixture instead of the kernel's own
// mount table.
func mountsFile(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mounts")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	setForTest(t, &procMounts, path)
}

// sizedDisks answers a size for the mounts a test names and refuses the rest.
func sizedDisks(t *testing.T, sizes map[string]uint64) {
	t.Helper()
	setForTest(t, &readDiskUsage, func(mount string) (DiskUsage, error) {
		size, known := sizes[mount]
		if !known {
			return DiskUsage{}, errNoReading
		}
		return DiskUsage{TotalBytes: size, Mount: mount}, nil
	})
}

// mountNames is what the reading reported, in the order it reported it.
func mountNames(disks []DiskUsage) []string {
	names := make([]string, 0, len(disks))
	for _, disk := range disks {
		names = append(names, disk.Mount)
	}
	return names
}

// The dashboard shows one row per real filesystem. A pseudo filesystem, a
// container's own mount and a bind mount of a device already listed would each
// add a row for storage the operator does not have.
func TestReadDisksReportsEveryRealFilesystemOnce(t *testing.T) {
	cases := []struct {
		name   string
		mounts string
		sizes  map[string]uint64
		want   []string
	}{
		{name: "a pseudo filesystem", mounts: "proc /proc proc rw 0 0\ntmpfs /tmp tmpfs rw 0 0\n/dev/sda1 / xfs rw 0 0\n",
			sizes: map[string]uint64{"/": 100}, want: []string{"/"}},
		{name: "a mount under a skipped prefix",
			mounts: "/dev/sda1 / xfs rw 0 0\noverlay /var/lib/docker/overlay2/x overlay rw 0 0\n",
			sizes:  map[string]uint64{"/": 100, "/var/lib/docker/overlay2/x": 5}, want: []string{"/"}},
		{name: "the same mount twice",
			mounts: "/dev/sda1 / xfs rw 0 0\n/dev/sda1 / xfs rw 0 0\n",
			sizes:  map[string]uint64{"/": 100}, want: []string{"/"}},
		{name: "a bind mount of a device already listed",
			mounts: "/dev/sda1 / xfs rw 0 0\n/dev/sda1 /home/c_test xfs rw 0 0\n",
			sizes:  map[string]uint64{"/": 100, "/home/c_test": 100}, want: []string{"/"}},
		{name: "a mount whose size cannot be read",
			mounts: "/dev/sda1 / xfs rw 0 0\n/dev/sdb1 /data xfs rw 0 0\n",
			sizes:  map[string]uint64{"/": 100}, want: []string{"/"}},
		{name: "a line with fewer fields than a mount has",
			mounts: "broken\n/dev/sda1 / xfs rw 0 0\n",
			sizes:  map[string]uint64{"/": 100}, want: []string{"/"}},
		{name: "a mount that is exactly a skipped prefix",
			mounts: "/dev/sdc1 /run xfs rw 0 0\n/dev/sda1 / xfs rw 0 0\n",
			sizes:  map[string]uint64{"/": 100, "/run": 5}, want: []string{"/"}},
		{name: "two filesystems, reported in mount order",
			mounts: "/dev/sdb1 /data xfs rw 0 0\n/dev/sda1 / xfs rw 0 0\n",
			sizes:  map[string]uint64{"/": 100, "/data": 200}, want: []string{"/", "/data"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mountsFile(t, tc.mounts)
			sizedDisks(t, tc.sizes)
			if got := mountNames(ReadDisks()); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("mounts = %v, want %v", got, tc.want)
			}
		})
	}
}

// A mount table the panel cannot read is reported as no disks rather than as an
// empty server.
func TestReadDisksReportsNothingWithoutAMountTable(t *testing.T) {
	setForTest(t, &procMounts, filepath.Join(t.TempDir(), "missing"))
	if disks := ReadDisks(); disks != nil {
		t.Errorf("disks = %+v, want none", disks)
	}
}

// netDevFile points the network reading at a fixture, and clears the rate
// baseline so one test cannot see another's counters.
func netDevFile(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dev")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	setForTest(t, &procNetDev, path)
	networkMu.Lock()
	previous := previousNetwork
	previousNetwork = map[string]networkSnapshot{}
	networkMu.Unlock()
	t.Cleanup(func() {
		networkMu.Lock()
		previousNetwork = previous
		networkMu.Unlock()
	})
}

// The dashboard graphs ONE interface, so the busiest real one is chosen and
// every virtual one is left out: a bridge or a container veth carries the same
// traffic twice.
func TestReadNetworkPicksTheBusiestRealInterface(t *testing.T) {
	netDevFile(t, `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets
    lo: 999999    10    0    0    0     0          0         0  999999    10    0    0    0     0       0          0
  eth0: 3000       10    0    0    0     0          0         0  1500      10    0    0    0     0       0          0
  eth1: 100        10    0    0    0     0          0         0  50        10    0    0    0     0       0          0
docker0: 500000    10    0    0    0     0          0         0  500000    10    0    0    0     0       0          0
`)

	usage := ReadNetwork()
	if usage.Interface != "eth0" {
		t.Fatalf("interface = %q, want eth0", usage.Interface)
	}
	if usage.RxTotalBytes != 3000 || usage.TxTotalBytes != 1500 {
		t.Errorf("totals = %d/%d, want 3000/1500", usage.RxTotalBytes, usage.TxTotalBytes)
	}
	if usage.RxBytes != 0 || usage.TxBytes != 0 {
		t.Errorf("rates = %d/%d, want none on the first reading", usage.RxBytes, usage.TxBytes)
	}
}

// The rate is the difference against the previous reading over the time between
// them, and a counter that went backwards (a reboot, or a driver reset) reports
// zero rather than a negative rate.
func TestReadNetworkRatesAreMeasuredAgainstThePreviousReading(t *testing.T) {
	for _, tc := range []struct {
		name       string
		previousRx int64
		previousTx int64
		wantRate   bool
	}{
		{name: "counters that grew", previousRx: 1000, previousTx: 500, wantRate: true},
		{name: "counters that went backwards", previousRx: 9000, previousTx: 9000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			netDevFile(t, "  eth0: 3000 10 0 0 0 0 0 0 1500 10 0 0 0 0 0 0\n")
			networkMu.Lock()
			previousNetwork["eth0"] = networkSnapshot{
				rx: tc.previousRx, tx: tc.previousTx, t: time.Now().Add(-2 * time.Second),
			}
			networkMu.Unlock()

			usage := ReadNetwork()
			assertRate(t, usage.RxBytes, tc.wantRate)
			assertRate(t, usage.TxBytes, tc.wantRate)
		})
	}
}

// assertRate checks a rate is either a plausible per-second figure or zero.
func assertRate(t *testing.T, rate int64, wanted bool) {
	t.Helper()
	switch {
	case wanted && (rate <= 0 || rate > 1000):
		t.Errorf("rate = %d, want the counter difference over about two seconds", rate)
	case !wanted && rate != 0:
		t.Errorf("rate = %d, want zero for a counter that went backwards", rate)
	}
}

// A reading with nothing usable in it is reported as no interface at all, not
// as an interface with zero traffic.
func TestReadNetworkReportsNothingWithoutARealInterface(t *testing.T) {
	for _, tc := range []struct{ name, content string }{
		{name: "only virtual interfaces", content: "    lo: 1 2 3 4 5 6 7 8 9 10\n  veth0: 1 2 3 4 5 6 7 8 9 10\n"},
		{name: "a line with too few counters", content: "  eth0: 1 2 3\n"},
		{name: "a line with no interface name", content: "no colon here\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			netDevFile(t, tc.content)
			if usage := ReadNetwork(); usage != (NetworkUsage{}) {
				t.Errorf("usage = %+v, want the zero value", usage)
			}
		})
	}
}

// A network reading with no file behind it is the zero value.
func TestReadNetworkReportsNothingWithoutTheKernelFile(t *testing.T) {
	setForTest(t, &procNetDev, filepath.Join(t.TempDir(), "missing"))
	if usage := ReadNetwork(); usage != (NetworkUsage{}) {
		t.Errorf("usage = %+v, want the zero value", usage)
	}
}

// hostInterfaces answers with the interfaces and addresses a test describes.
func hostInterfaces(t *testing.T, ifaces []net.Interface, addrs map[string][]net.Addr) {
	t.Helper()
	setForTest(t, &netInterfaces, func() ([]net.Interface, error) { return ifaces, nil })
	setForTest(t, &netAddrs, func(iface net.Interface) ([]net.Addr, error) { return addrs[iface.Name], nil })
}

// addr builds one interface address.
func addr(cidr string) net.Addr {
	ip, network, _ := net.ParseCIDR(cidr)
	network.IP = ip
	return network
}

// The address this returns is what the panel publishes as the server's own, so
// a bridge address or a private one behind NAT would send customers to the
// wrong place.
func TestPrimaryIPPrefersAPublicAddressOnARealInterface(t *testing.T) {
	up := net.FlagUp
	cases := []struct {
		name   string
		ifaces []net.Interface
		addrs  map[string][]net.Addr
		want   string
	}{
		{name: "a public address", want: "203.0.113.10",
			ifaces: []net.Interface{{Name: "eth0", Flags: up}},
			addrs:  map[string][]net.Addr{"eth0": {addr("203.0.113.10/24")}}},
		{name: "a bridge ahead of the real interface", want: "203.0.113.10",
			ifaces: []net.Interface{{Name: "docker0", Flags: up}, {Name: "eth0", Flags: up}},
			addrs: map[string][]net.Addr{
				"docker0": {addr("198.51.100.1/24")},
				"eth0":    {addr("203.0.113.10/24")},
			}},
		{name: "an interface that is down", want: "203.0.113.10",
			ifaces: []net.Interface{{Name: "eth0"}, {Name: "eth1", Flags: up}},
			addrs: map[string][]net.Addr{
				"eth0": {addr("198.51.100.1/24")},
				"eth1": {addr("203.0.113.10/24")},
			}},
		{name: "an IPv6 address ahead of the IPv4 one", want: "203.0.113.10",
			ifaces: []net.Interface{{Name: "eth0", Flags: up}},
			addrs:  map[string][]net.Addr{"eth0": {addr("2001:db8::1/64"), addr("203.0.113.10/24")}}},
		{name: "a private address ahead of the public one on the same interface", want: "203.0.113.10",
			ifaces: []net.Interface{{Name: "eth0", Flags: up}},
			addrs:  map[string][]net.Addr{"eth0": {addr("10.0.0.5/24"), addr("203.0.113.10/24")}}},
		{name: "a NAT interface ahead of the public one", want: "203.0.113.10",
			ifaces: []net.Interface{{Name: "eth0", Flags: up}, {Name: "eth1", Flags: up}},
			addrs: map[string][]net.Addr{
				"eth0": {addr("192.168.1.20/24")},
				"eth1": {addr("203.0.113.10/24")},
			}},
		// Nothing public: the fallback takes the first address of any interface
		// that is not loopback, virtual or not.
		{name: "only private addresses", want: "10.0.0.5",
			ifaces: []net.Interface{{Name: "eth0", Flags: up}},
			addrs:  map[string][]net.Addr{"eth0": {addr("10.0.0.5/24")}}},
		{name: "no IPv4 anywhere",
			ifaces: []net.Interface{{Name: "eth0", Flags: up}},
			addrs:  map[string][]net.Addr{"eth0": {addr("2001:db8::1/64")}}},
		{name: "no interface at all", ifaces: []net.Interface{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hostInterfaces(t, tc.ifaces, tc.addrs)
			if got := primaryIP(); got != tc.want {
				t.Errorf("primaryIP() = %q, want %q", got, tc.want)
			}
		})
	}
}

// An interface whose addresses cannot be read is skipped, not treated as one
// without an address: the next interface still gets its turn.
func TestPrimaryIPSkipsAnInterfaceItCannotRead(t *testing.T) {
	setForTest(t, &netInterfaces, func() ([]net.Interface, error) {
		return []net.Interface{{Name: "eth0", Flags: net.FlagUp}, {Name: "eth1", Flags: net.FlagUp}}, nil
	})
	setForTest(t, &netAddrs, func(iface net.Interface) ([]net.Addr, error) {
		if iface.Name == "eth0" {
			return nil, errNoReading
		}
		return []net.Addr{addr("203.0.113.10/24")}, nil
	})

	if got := primaryIP(); got != "203.0.113.10" {
		t.Errorf("primaryIP() = %q, want the address of the interface that answered", got)
	}
}

// A mount table that opens but cannot be read through is reported as no disks,
// the same as one that is not there at all.
func TestReadDisksReportsNothingWhenTheTableCannotBeRead(t *testing.T) {
	setForTest(t, &procMounts, t.TempDir()) // a directory opens, then refuses to read
	sizedDisks(t, nil)
	if disks := ReadDisks(); disks != nil {
		t.Errorf("disks = %+v, want none", disks)
	}
}

// The same for the network counters.
func TestReadNetworkReportsNothingWhenTheCountersCannotBeRead(t *testing.T) {
	setForTest(t, &procNetDev, t.TempDir())
	if usage := ReadNetwork(); usage != (NetworkUsage{}) {
		t.Errorf("usage = %+v, want the zero value", usage)
	}
}

// A host whose interfaces cannot be listed reports no address rather than a
// guess.
func TestPrimaryIPReportsNothingWhenTheInterfacesCannotBeRead(t *testing.T) {
	setForTest(t, &netInterfaces, func() ([]net.Interface, error) { return nil, errNoReading })
	if got := primaryIP(); got != "" {
		t.Errorf("primaryIP() = %q, want none", got)
	}
}

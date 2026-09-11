//go:build linux

package antivirus

import (
	"os/user"

	"golang.org/x/sys/unix"

	"servika/internal/chains"
	"servika/internal/notifications"
)

// The kernel interfaces the two watchers read, and where the process watcher's
// verdicts go. Each is a variable whose default is the call this package made
// before, so a test can run the event loops without CAP_SYS_ADMIN or
// CAP_NET_ADMIN and without a real process to inspect.

// The file watcher's fanotify descriptor.
var (
	fanotifyInit = unix.FanotifyInit
	fanotifyMark = unix.FanotifyMark
	pollFDs      = unix.Poll
	readFD       = unix.Read
	closeFD      = unix.Close
)

// The process watcher's netlink socket, its view of one process, and its alerts.
var (
	recvNetlink       = unix.Recvfrom
	readProcExe       = procExe
	readProcCmdline   = procCmdline
	readProcUID       = procUID
	readProcStat      = procStat
	lookupUserID      = user.LookupId
	writeNotification = notifications.Write
	writeChainEvent   = chains.WriteEvent
)

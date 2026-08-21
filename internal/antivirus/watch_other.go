//go:build !linux

package antivirus

// fanotify is a Linux interface. This build exists so the package compiles on a
// development machine; it never runs on a server, and it REFUSES rather than
// returning quietly, because a watcher that starts and watches nothing is worse
// than one that does not start.

import (
	"context"
	"errors"
)

func (w *watcher) run(context.Context) error {
	return errors.New("real-time watching needs fanotify, which is Linux only")
}

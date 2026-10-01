// SPDX-License-Identifier: AGPL-3.0-only

package tlsca

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// ErrLocked says the certificate set is being changed by another holder:
// `podaro setup`'s publish/rollback transaction, or a gateway renewal.
var ErrLocked = errors.New("the certificate set is locked")

// LockPath is where the lock lives: one file per state directory.
func LockPath(stateDir string) string { return filepath.Join(stateDir, "setup.lock") }

// Lock takes the exclusive lock that serializes every change to a state
// directory's certificate set — setup stages, publishes and rolls back
// under it, and a renewal issues and reads its new leaf under it — so no
// holder can observe two generations: a set exchanged between the issue
// and the read would otherwise put another domain's leaf into the live
// listener. Non-blocking: a caller that finds it
// held gets ErrLocked and comes back rather than queueing.
func Lock(stateDir string) (func(), error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(LockPath(stateDir), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, ErrLocked
	}
	return func() { f.Close() }, nil
}

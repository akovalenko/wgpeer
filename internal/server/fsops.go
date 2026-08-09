//go:build linux

package server

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// errLocked is returned when the flock cannot be acquired within the timeout.
var errLocked = errors.New("could not acquire lock")

// acquireLock takes an exclusive flock on a sidecar lock file (conf.lock), so
// the lock survives the atomic rename of the conf itself (spec §7). It retries
// until timeout, then returns errLocked.
func acquireLock(confPath string, timeout time.Duration) (*os.File, error) {
	f, err := os.OpenFile(confPath+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, errLocked
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func releaseLock(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
}

// atomicWrite writes data to a temp file in the same directory, fsyncs it, then
// renames over path — an atomic replace on one filesystem (spec §7, §10).
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".wgpeer-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // harmless no-op once renamed away
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil { // best-effort durable rename
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// applySyncconf applies only the peer delta to the live interface without
// touching the device or running wg-quick hooks (spec §7):
//
//	wg syncconf <iface> <(wg-quick strip <conf>)
func applySyncconf(iface, confPath string) error {
	var stripped, stripErr bytes.Buffer
	strip := exec.Command("wg-quick", "strip", confPath)
	strip.Stdout = &stripped
	strip.Stderr = &stripErr
	if err := strip.Run(); err != nil {
		return fmt.Errorf("wg-quick strip: %w: %s", err, stripErr.String())
	}
	var syncErr bytes.Buffer
	sync := exec.Command("wg", "syncconf", iface, "/dev/stdin")
	sync.Stdin = &stripped
	sync.Stderr = &syncErr
	if err := sync.Run(); err != nil {
		return fmt.Errorf("wg syncconf: %w: %s", err, syncErr.String())
	}
	return nil
}

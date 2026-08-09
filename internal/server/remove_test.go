//go:build linux

package server

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/akovalenko/wgpeer/internal/protocol"
)

// provideForRemove bootstraps an interface (conf + sidecar) under fresh temp dirs
// so a remove test has a realistic target to tear down. It reuses provideDirs and
// Provide from provide_test.go / provide.go (same package).
func provideForRemove(t *testing.T, iface string) (wgDir, sidecarDir string) {
	t.Helper()
	wgDir, sidecarDir = provideDirs(t)
	resp := Provide(ProvideOptions{
		Iface:      iface,
		Subnet:     netip.MustParsePrefix("172.19.0.0/16"),
		Endpoint:   "h",
		WGDir:      wgDir,
		SidecarDir: sidecarDir,
		Up:         false,
	})
	if !resp.OK {
		t.Fatalf("setup provide failed: %s", resp.Message)
	}
	return wgDir, sidecarDir
}

// stubDisable makes runDisable a no-op recording the iface, so tests never shell
// out to systemctl.
func stubDisable(t *testing.T) *string {
	t.Helper()
	got := new(string)
	t.Cleanup(stub(&runDisable, func(iface string) error { *got = iface; return nil }))
	return got
}

func TestRemove_backsUpAndDeletes(t *testing.T) {
	wgDir, sidecarDir := provideForRemove(t, "wg7")
	gotIface := stubDisable(t)
	t.Cleanup(stub(&nowFunc, func() time.Time { return time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC) }))

	confPath := filepath.Join(wgDir, "wg7.conf")
	sidecarPath := filepath.Join(sidecarDir, "wg7.toml")
	orig, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("read conf before remove: %v", err)
	}

	resp := Remove(RemoveOptions{Iface: "wg7", WGDir: wgDir, SidecarDir: sidecarDir})
	if !resp.OK {
		t.Fatalf("remove failed: %s", resp.Message)
	}
	if *gotIface != "wg7" {
		t.Errorf("runDisable got %q, want wg7", *gotIface)
	}
	if !resp.Disabled {
		t.Errorf("Disabled should be true when disable succeeds")
	}

	// Backup: correct path, 0600, byte-identical to the original conf.
	wantBak := confPath + ".bak-20260702"
	if resp.BackupPath != wantBak {
		t.Errorf("BackupPath = %q, want %q", resp.BackupPath, wantBak)
	}
	bfi, err := os.Stat(wantBak)
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}
	if bfi.Mode().Perm() != 0o600 {
		t.Errorf("backup perm = %o, want 600", bfi.Mode().Perm())
	}
	bak, err := os.ReadFile(wantBak)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(bak) != string(orig) {
		t.Errorf("backup content differs from original conf")
	}

	// Both live files are gone and reported as removed.
	if _, err := os.Stat(confPath); !os.IsNotExist(err) {
		t.Errorf("conf should be deleted, stat err = %v", err)
	}
	if _, err := os.Stat(sidecarPath); !os.IsNotExist(err) {
		t.Errorf("sidecar should be deleted, stat err = %v", err)
	}
	if !slices.Contains(resp.Removed, confPath) || !slices.Contains(resp.Removed, sidecarPath) {
		t.Errorf("Removed = %v, want both conf and sidecar", resp.Removed)
	}
	if resp.Message != "" {
		t.Errorf("no warnings expected on the clean path, got %q", resp.Message)
	}
}

func TestRemove_noBackup(t *testing.T) {
	wgDir, sidecarDir := provideForRemove(t, "wg0")
	stubDisable(t)

	resp := Remove(RemoveOptions{Iface: "wg0", WGDir: wgDir, SidecarDir: sidecarDir, NoBackup: true})
	if !resp.OK {
		t.Fatalf("remove failed: %s", resp.Message)
	}
	if resp.BackupPath != "" {
		t.Errorf("BackupPath = %q, want empty with --no-backup", resp.BackupPath)
	}
	// No .bak-* file should have been left behind next to the conf.
	matches, _ := filepath.Glob(filepath.Join(wgDir, "wg0.conf.bak-*"))
	if len(matches) != 0 {
		t.Errorf("no backup file expected, found %v", matches)
	}
	if _, err := os.Stat(filepath.Join(wgDir, "wg0.conf")); !os.IsNotExist(err) {
		t.Errorf("conf should still be deleted with --no-backup")
	}
}

func TestRemove_missingSidecarStillRemovesConf(t *testing.T) {
	stubDisable(t)
	t.Cleanup(stub(&nowFunc, func() time.Time { return time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC) }))
	root := t.TempDir()
	wgDir := filepath.Join(root, "wireguard")
	sidecarDir := filepath.Join(root, "wgpeer")
	if err := os.MkdirAll(wgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(wgDir, "wg9.conf")
	if err := os.WriteFile(confPath, []byte("[Interface]\nPrivateKey = k\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	resp := Remove(RemoveOptions{Iface: "wg9", WGDir: wgDir, SidecarDir: sidecarDir})
	if !resp.OK {
		t.Fatalf("remove failed: %s", resp.Message)
	}
	if resp.BackupPath == "" {
		t.Errorf("conf should have been backed up even without a sidecar")
	}
	if _, err := os.Stat(confPath); !os.IsNotExist(err) {
		t.Errorf("conf should be deleted")
	}
	if resp.Message == "" {
		t.Errorf("expected a note about the missing sidecar")
	}
}

func TestRemove_nothingToRemove(t *testing.T) {
	stubDisable(t)
	root := t.TempDir()
	resp := Remove(RemoveOptions{
		Iface:      "wg0",
		WGDir:      filepath.Join(root, "wireguard"),
		SidecarDir: filepath.Join(root, "wgpeer"),
	})
	if resp.OK {
		t.Fatal("expected failure when neither conf nor sidecar exists")
	}
	if resp.Error != protocol.ErrNotFound {
		t.Errorf("error = %q, want not_found", resp.Error)
	}
}

func TestRemove_disableFailureIsBestEffort(t *testing.T) {
	wgDir, sidecarDir := provideForRemove(t, "wg0")
	t.Cleanup(stub(&runDisable, func(string) error { return errBoom }))

	resp := Remove(RemoveOptions{Iface: "wg0", WGDir: wgDir, SidecarDir: sidecarDir})
	if !resp.OK {
		t.Fatalf("teardown should still succeed when disable fails: %s", resp.Message)
	}
	if resp.Disabled {
		t.Errorf("Disabled should be false when disable errors")
	}
	if resp.Message == "" {
		t.Errorf("disable failure should be noted in the report")
	}
	// Files are still removed despite the disable failure.
	if _, err := os.Stat(filepath.Join(wgDir, "wg0.conf")); !os.IsNotExist(err) {
		t.Errorf("conf should be deleted even when disable fails")
	}
}

func TestRemove_confPathFromSidecar(t *testing.T) {
	stubDisable(t)
	sidecarDir := t.TempDir()
	t.Setenv("WGPEER_CONFIG_DIR", sidecarDir)
	// The conf lives where the default <WGDir>/<iface>.conf resolver would NOT look;
	// only the sidecar's conf_path points at it.
	customDir := t.TempDir()
	confPath := filepath.Join(customDir, "somewhere-else.conf")
	if err := os.WriteFile(confPath, []byte("[Interface]\nPrivateKey = k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sidecarPath := filepath.Join(sidecarDir, "wgx.toml")
	sidecar := "conf_path = " + strconv.Quote(confPath) + "\nsubnet = \"10.0.0.0/24\"\n"
	if err := os.WriteFile(sidecarPath, []byte(sidecar), 0o644); err != nil {
		t.Fatal(err)
	}

	resp := Remove(RemoveOptions{Iface: "wgx", WGDir: filepath.Join(t.TempDir(), "wg"), SidecarDir: sidecarDir})
	if !resp.OK {
		t.Fatalf("remove failed: %s", resp.Message)
	}
	if resp.ConfPath != confPath {
		t.Errorf("ConfPath = %q, want %q (from sidecar conf_path)", resp.ConfPath, confPath)
	}
	if _, err := os.Stat(confPath); !os.IsNotExist(err) {
		t.Errorf("the sidecar-pointed conf should be deleted")
	}
	if _, err := os.Stat(sidecarPath); !os.IsNotExist(err) {
		t.Errorf("sidecar should be deleted")
	}
}

func TestRemove_deletesStaleLock(t *testing.T) {
	wgDir, sidecarDir := provideForRemove(t, "wg0")
	stubDisable(t)
	confPath := filepath.Join(wgDir, "wg0.conf")
	lockPath := confPath + ".lock"
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	resp := Remove(RemoveOptions{Iface: "wg0", WGDir: wgDir, SidecarDir: sidecarDir})
	if !resp.OK {
		t.Fatalf("remove failed: %s", resp.Message)
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Errorf("stale .lock should be deleted")
	}
	if !slices.Contains(resp.Removed, lockPath) {
		t.Errorf("Removed = %v, want the .lock", resp.Removed)
	}
}

func TestRemove_badIface(t *testing.T) {
	stubDisable(t)
	resp := Remove(RemoveOptions{Iface: "wg 0"})
	if resp.OK {
		t.Fatal("expected failure for an invalid interface name")
	}
	if resp.Error != protocol.ErrBadRequest {
		t.Errorf("error = %q, want bad_request", resp.Error)
	}
}

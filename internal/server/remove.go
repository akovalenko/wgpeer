package server

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/akovalenko/wgpeer/internal/config"
	"github.com/akovalenko/wgpeer/internal/protocol"
)

// runDisable and nowFunc are indirected through vars so tests can stub the two
// non-deterministic side effects: systemd (like runEnable in provide.go) and the
// wall clock used to stamp the backup filename.
var (
	runDisable = disableWgQuick
	nowFunc    = time.Now
)

// RemoveOptions parameterises interface teardown. WGDir/SidecarDir default to the
// live locations; tests point them at a temp dir.
type RemoveOptions struct {
	Iface      string
	NoBackup   bool   // skip the .conf backup (dangerous: the private key is only in the conf)
	WGDir      string // "" = WGDir()
	SidecarDir string // "" = config.ServerDir()
}

// RemovePlan is the resolved view of what a remove will touch, computed before any
// mutation so the CLI can print a confirmation summary. Remove recomputes it, so a
// caller may show the plan and then run Remove without threading it back through.
type RemovePlan struct {
	Iface         string
	ConfPath      string
	SidecarPath   string
	BackupPath    string // where the .conf would be copied; "" when --no-backup or no conf exists
	ConfExists    bool
	SidecarExists bool
}

// Plan resolves the interface's conf and sidecar paths and reports what exists,
// without touching anything. The conf path comes from the sidecar's conf_path when
// a sidecar is present (an interface may keep its .conf anywhere); otherwise it
// falls back to the conventional <WGDir>/<iface>.conf. Neither file existing is a
// not_found error — there is nothing to remove.
//
// It mirrors resolveEndpoints' house pattern: a non-nil *RemoveResponse is the
// error return (already carrying an error code + message), nil on success.
func Plan(opts RemoveOptions) (RemovePlan, *protocol.RemoveResponse) {
	if err := validIface(opts.Iface); err != nil {
		e := removeErr(protocol.ErrBadRequest, err.Error())
		return RemovePlan{}, &e
	}

	wgDir := opts.WGDir
	if wgDir == "" {
		wgDir = WGDir()
	}
	sidecarDir := opts.SidecarDir
	if sidecarDir == "" {
		sidecarDir = config.ServerDir()
	}
	sidecarPath := filepath.Join(sidecarDir, opts.Iface+".toml")

	sidecarExists, confPath, err := readSidecarConfPath(sidecarPath, filepath.Join(wgDir, opts.Iface+".conf"))
	if err != nil {
		e := removeErr(protocol.ErrInternal, err.Error())
		return RemovePlan{}, &e
	}

	confExists, err := fileExists(confPath)
	if err != nil {
		e := removeErr(protocol.ErrInternal, err.Error())
		return RemovePlan{}, &e
	}

	if !sidecarExists && !confExists {
		e := removeErr(protocol.ErrNotFound, fmt.Sprintf(
			"interface %q: neither sidecar (%s) nor conf (%s) exists — nothing to remove",
			opts.Iface, sidecarPath, confPath))
		return RemovePlan{}, &e
	}

	plan := RemovePlan{
		Iface:         opts.Iface,
		ConfPath:      confPath,
		SidecarPath:   sidecarPath,
		ConfExists:    confExists,
		SidecarExists: sidecarExists,
	}
	if !opts.NoBackup && confExists {
		plan.BackupPath = confPath + ".bak-" + nowFunc().Format("20060102")
	}
	return plan, nil
}

// Remove tears the interface down: back up the conf (unless --no-backup), stop and
// disable wg-quick, then delete the conf, sidecar, and stale lock. The order is
// load-bearing — the backup and the wg-quick down both need the conf still on disk,
// so files are deleted last (see the plan). Every step is best-effort past the
// point of no return: a disable that fails (unit not enabled, already down) or a
// stray already-gone file does not abort the teardown; it is noted in the report.
func Remove(opts RemoveOptions) protocol.RemoveResponse {
	plan, errResp := Plan(opts)
	if errResp != nil {
		return *errResp
	}

	resp := protocol.RemoveResponse{
		Status:      protocol.Status{OK: true},
		Iface:       plan.Iface,
		ConfPath:    plan.ConfPath,
		SidecarPath: plan.SidecarPath,
	}
	var warnings []string
	if !plan.SidecarExists {
		warnings = append(warnings, "no sidecar found (interface may be hand-managed)")
	}

	// 1. Backup the key-bearing conf while it still exists.
	if plan.BackupPath != "" {
		data, err := os.ReadFile(plan.ConfPath)
		if err != nil {
			return removeErr(protocol.ErrInternal, "reading conf for backup: "+err.Error())
		}
		if err := atomicWrite(plan.BackupPath, data, 0o600); err != nil {
			return removeErr(protocol.ErrInternal, "writing backup "+plan.BackupPath+": "+err.Error())
		}
		resp.BackupPath = plan.BackupPath
	}

	// 2. Stop and disable wg-quick — best-effort (must happen before the conf is
	//    deleted, since `--now` runs `wg-quick down` off the conf).
	if err := runDisable(plan.Iface); err != nil {
		warnings = append(warnings, "disable failed (interface may still be up): "+err.Error())
	} else {
		resp.Disabled = true
	}

	// 3. Delete the files (conf, sidecar, and any stale lock). Best-effort per file.
	for _, p := range []string{plan.ConfPath, plan.SidecarPath, plan.ConfPath + ".lock"} {
		removed, err := removeIfExists(p)
		if err != nil {
			warnings = append(warnings, "deleting "+p+": "+err.Error())
			continue
		}
		if removed {
			resp.Removed = append(resp.Removed, p)
		}
	}

	if len(warnings) > 0 {
		resp.Message = strings.Join(warnings, "; ")
	}
	return resp
}

// readSidecarConfPath reports whether the sidecar exists and returns the conf path
// to operate on: the sidecar's conf_path when present and non-empty, else the
// supplied default. A missing sidecar is not an error (returns exists=false); a
// present-but-unparseable or unreadable sidecar surfaces the error. A parseable
// sidecar with an empty conf_path falls back to the default.
func readSidecarConfPath(sidecarPath, defaultConf string) (exists bool, confPath string, err error) {
	data, err := os.ReadFile(sidecarPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, defaultConf, nil
		}
		return false, "", fmt.Errorf("reading sidecar %s: %w", sidecarPath, err)
	}
	var sc struct {
		ConfPath string `toml:"conf_path"`
	}
	if err := toml.Unmarshal(data, &sc); err != nil {
		return true, "", fmt.Errorf("parsing sidecar %s: %w", sidecarPath, err)
	}
	if sc.ConfPath == "" {
		return true, defaultConf, nil
	}
	return true, sc.ConfPath, nil
}

// fileExists reports whether path exists. A stat error other than NotExist is
// surfaced rather than silently treated as absent.
func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("checking %s: %w", path, err)
}

// removeIfExists deletes path, reporting whether it was there. A NotExist is not an
// error (idempotent teardown); anything else is.
func removeIfExists(path string) (bool, error) {
	err := os.Remove(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// disableWgQuick stops the interface and removes it from boot in one step — the
// inverse of enableWgQuick's `enable --now`.
func disableWgQuick(iface string) error {
	var errb bytes.Buffer
	cmd := exec.Command("systemctl", "disable", "--now", "wg-quick@"+iface)
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl disable --now wg-quick@%s: %w: %s", iface, err, strings.TrimSpace(errb.String()))
	}
	return nil
}

func removeErr(code, msg string) protocol.RemoveResponse {
	return protocol.RemoveResponse{Status: protocol.Status{OK: false, Error: code, Message: msg}}
}

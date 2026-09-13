package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"retune/internal/protocol"
)

// Escrower sends a recovery password to the server.
type Escrower interface {
	// HasRecoveryKey reports whether the server already holds one for a volume.
	HasRecoveryKey(ctx context.Context, volumeID string) (bool, error)
	EscrowRecoveryKey(ctx context.Context, volumeID, method, recoveryPassword string) error
}

// BitLockerHandler requires the operating system drive to be encrypted, and
// escrows its recovery password.
//
// It never decrypts a drive and never starts encryption unless the setting asks
// for it, which is why it implements no Revert: undoing encryption is not
// something a profile going out of scope should do to a laptop.
type BitLockerHandler struct {
	Run    PowerShell
	Escrow Escrower
}

func (BitLockerHandler) Kind() string { return protocol.KindBitLocker }

func (h BitLockerHandler) run(ctx context.Context, script string) (string, error) {
	if h.Run == nil {
		return "", errors.New("bitlocker settings are only supported on Windows")
	}
	return h.Run(ctx, script)
}

// volumeStatus is what the BitLocker cmdlets report about the OS volume.
type volumeStatus struct {
	MountPoint       string `json:"mount_point"`
	ProtectionStatus string `json:"protection_status"`
	VolumeStatus     string `json:"volume_status"`
	EncryptionMethod string `json:"encryption_method"`
	RecoveryPassword string `json:"recovery_password"`
	TPMPresent       bool   `json:"tpm_present"`
}

// statusScript reads the OS volume and whether a TPM is present. The recovery
// password comes back too, because escrowing it is the point; it is never
// logged.
const statusScript = `$v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
if (-not $v) { '' ; exit 0 }
$rp = ($v.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -First 1).RecoveryPassword
$tpm = $false
try { $tpm = [bool](Get-Tpm -ErrorAction Stop).TpmPresent } catch { $tpm = $false }
[pscustomobject]@{
  mount_point       = [string]$v.MountPoint
  protection_status = [string]$v.ProtectionStatus
  volume_status     = [string]$v.VolumeStatus
  encryption_method = [string]$v.EncryptionMethod
  recovery_password = [string]$rp
  tpm_present       = $tpm
} | ConvertTo-Json -Compress`

func (h BitLockerHandler) status(ctx context.Context) (volumeStatus, bool, error) {
	out, err := h.run(ctx, statusScript)
	if err != nil {
		return volumeStatus{}, false, err
	}
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return volumeStatus{}, false, nil
	}
	var status volumeStatus
	if err := json.Unmarshal([]byte(trimmed), &status); err != nil {
		return volumeStatus{}, false, fmt.Errorf("read the BitLocker status: %w", err)
	}
	return status, true, nil
}

func (h BitLockerHandler) Get(ctx context.Context, _ protocol.Setting) (State, error) {
	status, found, err := h.status(ctx)
	if err != nil || !found {
		return State{}, err
	}
	// The recovery password is never kept in local state: it is escrowed to the
	// server and nowhere else.
	status.RecoveryPassword = ""
	raw, err := json.Marshal(status)
	if err != nil {
		return State{}, err
	}
	return State{Exists: strings.EqualFold(status.ProtectionStatus, "On"), Data: raw}, nil
}

func (h BitLockerHandler) Test(ctx context.Context, s protocol.Setting) (bool, error) {
	status, found, err := h.status(ctx)
	if err != nil {
		return false, err
	}
	if !found {
		return false, errors.New("this machine has no BitLocker volume for the system drive")
	}
	if !strings.EqualFold(status.ProtectionStatus, "On") {
		return false, nil
	}
	if s.Method != "" && !strings.EqualFold(status.EncryptionMethod, s.Method) {
		// Already encrypted with something else. Say so rather than trying to
		// re-encrypt a drive, which would be destructive and slow.
		return false, fmt.Errorf("the system drive is encrypted with %s, not %s; Retune will not re-encrypt it",
			status.EncryptionMethod, s.Method)
	}
	if !s.EscrowRecoveryKey {
		return true, nil
	}
	if h.Escrow == nil {
		return false, errors.New("this agent cannot escrow a recovery key")
	}
	return h.Escrow.HasRecoveryKey(ctx, status.MountPoint)
}

func (h BitLockerHandler) Set(ctx context.Context, s protocol.Setting) error {
	if !s.RequireEncryption {
		// Nothing is required, so nothing is done. A profile never turns
		// encryption off.
		return nil
	}
	status, found, err := h.status(ctx)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("this machine has no BitLocker volume for the system drive")
	}

	if !strings.EqualFold(status.ProtectionStatus, "On") {
		if !status.TPMPresent {
			return errors.New("this machine has no TPM, so BitLocker cannot be enabled without a startup key")
		}
		method := s.Method
		if method == "" {
			method = protocol.XtsAes256
		}
		script := "Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod " + method +
			" -TpmProtector -UsedSpaceOnly -SkipHardwareTest | Out-Null"
		if _, err := h.run(ctx, script); err != nil {
			return fmt.Errorf("enable BitLocker: %w", err)
		}
		// Encryption runs in the background; the next check-in sees the result.
		status, _, err = h.status(ctx)
		if err != nil {
			return err
		}
	}

	if !s.EscrowRecoveryKey {
		return nil
	}
	if status.RecoveryPassword == "" {
		if _, err := h.run(ctx,
			"Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector | Out-Null"); err != nil {
			return fmt.Errorf("add a recovery password: %w", err)
		}
		if status, _, err = h.status(ctx); err != nil {
			return err
		}
	}
	if status.RecoveryPassword == "" {
		return errors.New("the volume has no recovery password to escrow")
	}
	if h.Escrow == nil {
		return errors.New("this agent cannot escrow a recovery key")
	}
	return h.Escrow.EscrowRecoveryKey(ctx, status.MountPoint, status.EncryptionMethod, status.RecoveryPassword)
}

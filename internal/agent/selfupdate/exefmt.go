package selfupdate

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"fmt"
	"runtime"
)

// ErrWrongPlatform is returned by CheckExecutable for a file that is not an
// executable this machine can run.
var ErrWrongPlatform = errors.New("not an executable for this machine")

// CheckExecutable reports whether the file at path is an executable for this
// machine's operating system and processor. See CheckExecutableFor.
func CheckExecutable(path string) error {
	return CheckExecutableFor(path, runtime.GOOS, runtime.GOARCH)
}

// CheckExecutableFor reports whether the file at path is an executable for
// goos and goarch. The release signature covers a build's version and hash,
// not what it runs on, so a server that hands a Mac the Windows build of the
// right version would pass every other check; swapping it in would take the
// agent down until the rollback deadline. Reading the header first turns that
// into a refusal before the service is touched.
func CheckExecutableFor(path, goos, goarch string) error {
	switch goos {
	case "windows":
		f, err := pe.Open(path)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrWrongPlatform, err)
		}
		defer f.Close()
		want := map[string]uint16{"amd64": pe.IMAGE_FILE_MACHINE_AMD64, "arm64": pe.IMAGE_FILE_MACHINE_ARM64, "386": pe.IMAGE_FILE_MACHINE_I386}
		if m, ok := want[goarch]; !ok || f.Machine != m {
			return fmt.Errorf("%w: a Windows executable for machine %#x, not %s", ErrWrongPlatform, f.Machine, goarch)
		}
		return nil
	case "darwin":
		want := map[string]macho.Cpu{"amd64": macho.CpuAmd64, "arm64": macho.CpuArm64}
		cpu, ok := want[goarch]
		if !ok {
			return fmt.Errorf("%w: no Mach-O processor for %s", ErrWrongPlatform, goarch)
		}
		// A universal binary is one file holding a build per processor.
		if fat, err := macho.OpenFat(path); err == nil {
			defer fat.Close()
			for _, a := range fat.Arches {
				if a.Cpu == cpu && a.Type == macho.TypeExec {
					return nil
				}
			}
			return fmt.Errorf("%w: a universal binary with no %s executable", ErrWrongPlatform, goarch)
		}
		f, err := macho.Open(path)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrWrongPlatform, err)
		}
		defer f.Close()
		if f.Cpu != cpu || f.Type != macho.TypeExec {
			return fmt.Errorf("%w: a Mach-O file for %v, not an %s executable", ErrWrongPlatform, f.Cpu, goarch)
		}
		return nil
	case "linux":
		f, err := elf.Open(path)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrWrongPlatform, err)
		}
		defer f.Close()
		want := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64, "386": elf.EM_386, "arm": elf.EM_ARM}
		if m, ok := want[goarch]; !ok || f.Machine != m {
			return fmt.Errorf("%w: an ELF file for %v, not %s", ErrWrongPlatform, f.Machine, goarch)
		}
		if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
			return fmt.Errorf("%w: an ELF file of type %v, not an executable", ErrWrongPlatform, f.Type)
		}
		return nil
	}
	return fmt.Errorf("%w: self-update does not know %s executables", ErrWrongPlatform, goos)
}

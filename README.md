# Blackbird Adversary Emulation Suite

The Blackbird Adversary Emulation Suite is an extension of Blackbird for validating Blackbird telemetry,
correlation, and detection coverage in controlled defensive labs.

This repository is not a general-purpose offensive toolkit. It exists to exercise Blackbird's sensors and
detection logic with inert, bounded samples. The samples are designed for Blackbird capability testing only and
must not be used for intrusion, post-exploitation, evasion development, unauthorized monitoring, or any other
dual-use/offensive purpose.

## Layout

- `VCXProj/` - Visual Studio solution and project files.
- `src/` and `include/` - core AES console application sources.
- `common/` - shared sample dispatcher and support code.
- `apc/`, `beacon/`, `hollowing/`, `injection/`, `kerberos/`, `loader/`, `lotl/`, `lpe/`, `mem/`, `network/`, `process/`,
  `registry/`, `service/`, `sxs/`, `syscall/`, `benign/` - sample categories built by the category vcxprojs.
- `manifests/` - Blackbird detection and protection audit metadata.
- `Scripts/` - AES helper scripts, including protection benchmark manifest validation and sync.

## Build

Open `AES.slnx` or build with MSBuild:

```powershell
msbuild AES.slnx /t:Build /p:Configuration=Release /p:Platform=x64 /m
```

Build outputs are generated under platform/configuration directories such as `x64/Release/` and are intentionally
ignored by git.

To build a single sample category:

```powershell
msbuild VCXProj\AES.Samples.Syscall.vcxproj /t:Build /p:Configuration=Release /p:Platform=x64
```

The sample build script is `Build.ps1`. It generates `manifests/aes.samples.generated.json` from the
suite build metadata; that generated inventory is ignored by git.

Protection benchmarks are metadata-driven and do not build a native sample binary. Validate or install the
Blackbird anti-VM protection manifest with:

```powershell
.\Scripts\Install-BlackbirdProtectionBenchmarks.ps1 -ValidateOnly
.\Scripts\Install-BlackbirdProtectionBenchmarks.ps1 -BkaesRoot "C:\.cyberwp\BLACKBIRD COLLECTIVE\Adversary Emulation Suite" -Force
```

## PostProcessInitRoutine Loader Exercises

The x64 `loader` category contains two bounded fixtures for the writable
`PEB.PostProcessInitRoutine` loader callback:

- `bb_det_post_process_init_prepatched.exe` is post-link modified by
  `Scripts/Add-PostProcessInitRoutineSection.ps1`. The patcher appends a `.ppir`
  executable image section containing an inert callback. The launcher creates a
  copy of itself suspended and writes that section's mapped address into the
  child's PEB field.
- `bb_det_post_process_init_remote_patch.exe` creates a copy of itself
  suspended, writes the same inert callback into a reserved executable section
  in the child's mapped image, writes that address into the PEB field, and
  resumes the initial thread.

A PE optional header has no field that initializes `PostProcessInitRoutine`;
the loader reads the runtime PEB field. Consequently, even the post-link
modified fixture must perform the PEB write after process creation.

Each fixture blocks inside the callback until its parent observes the callback
state while the normal entry marker remains unset. The parent then releases the
callback and requires the normal entry marker and a zero process exit. Those
self-checks are supplemented by production telemetry expectations in the suite
manifest. Validation covered 10 independent runs per positive fixture and
causal negative controls that execute the same binaries without the PEB write;
the positives required `POST_PROCESS_INIT_ROUTINE_HIJACK` at `NtResumeThread`
and the controls forbade it.

## License And Use Limits

This project is DSGL code and is governed by the `LICENSE` in this directory, as an extension of the Blackbird
Community license. Use is limited to authorized defensive testing of Blackbird. Do not redistribute generated
executables, DLLs, symbols, intermediate files, or Visual Studio local state.

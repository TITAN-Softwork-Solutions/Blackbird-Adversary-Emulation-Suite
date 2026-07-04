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
- `apc/`, `beacon/`, `hollowing/`, `injection/`, `kerberos/`, `lotl/`, `lpe/`, `mem/`, `network/`, `process/`,
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

## License And Use Limits

This project is DSGL code and is governed by the `LICENSE` in this directory, as an extension of the Blackbird
Community license. Use is limited to authorized defensive testing of Blackbird. Do not redistribute generated
executables, DLLs, symbols, intermediate files, or Visual Studio local state.

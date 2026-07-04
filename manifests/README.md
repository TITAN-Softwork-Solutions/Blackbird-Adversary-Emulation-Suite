# Blackbird Detection Audit Manifests

`blackbird.detections.json` is the authoritative audit manifest for `BlackbirdRunner --detection-audit`.
`blackbird.protection.json` contains platform protection benchmarks, including the anti-VM identity probe
cases that execute through `BlackbirdRunner.exe`.

Run a focused case:

```powershell
$env:PATH = (Resolve-Path ".\Enterprise\x64\Debug").Path + ";" + $env:PATH
.\Enterprise\x64\Debug\net9.0-windows\BlackbirdRunner.exe --detection-audit --suite-root ".\Adversary Emulation Suite" --filter direct_syscall_handle --scan-seconds 30 --out-dir ".\artifacts\detection-audit\direct-syscall"
```

Run the full suite:

```powershell
$env:PATH = (Resolve-Path ".\Enterprise\x64\Debug").Path + ";" + $env:PATH
.\Enterprise\x64\Debug\net9.0-windows\BlackbirdRunner.exe --detection-audit --suite-root ".\Adversary Emulation Suite" --out-dir ".\artifacts\detection-audit\full"
```

`J58.dll` must be next to the runner, in the current working directory, installed under Program Files, or on `PATH`.

Case binaries are resolved from the manifest path first. The AES build script places sample binaries in `x64\Release` by default.
`Build-AESSamples.ps1` also writes `aes.samples.generated.json` here as a generated sample inventory; detection
expectations remain in `blackbird.detections.json`.

Protection benchmarks are resolved the same way as detection cases, but may point at Blackbird platform
tools instead of AES sample binaries when the test validates analysis-environment concealment rather than
sample behavior.

Use `Scripts\Install-BlackbirdProtectionBenchmarks.ps1` to validate the protection manifest or sync it into
an installed AES root. The helper also writes `benchmarks\manifest.json` as a legacy compatibility shim for
older runner/server paths; `manifests\blackbird.protection.json` remains the source of truth.

The runner writes `blackbird-detection-audit.json`, `blackbird-detection-audit.md`, `junit.xml`, and one per-case folder containing the capture archive plus `result.json` and `facts.json`.

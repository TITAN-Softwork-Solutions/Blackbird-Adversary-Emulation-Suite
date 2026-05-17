# Blackbird Detection Audit Manifests

`blackbird.detections.json` is the authoritative audit manifest for `BlackbirdRunner --detection-audit`.

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

The runner writes `blackbird-detection-audit.json`, `blackbird-detection-audit.md`, `junit.xml`, and one per-case folder containing the capture archive plus `result.json` and `facts.json`.

param(
    [Parameter(Mandatory = $true)]
    [string]$Path
)

$ErrorActionPreference = "Stop"

function Read-U16 {
    param([byte[]]$Buffer, [int]$Offset)
    return [BitConverter]::ToUInt16($Buffer, $Offset)
}

function Read-U32 {
    param([byte[]]$Buffer, [int]$Offset)
    return [BitConverter]::ToUInt32($Buffer, $Offset)
}

function Write-U16 {
    param([byte[]]$Buffer, [int]$Offset, [uint16]$Value)
    [BitConverter]::GetBytes($Value).CopyTo($Buffer, $Offset)
}

function Write-U32 {
    param([byte[]]$Buffer, [int]$Offset, [uint32]$Value)
    [BitConverter]::GetBytes($Value).CopyTo($Buffer, $Offset)
}

function Align-Up {
    param([uint64]$Value, [uint64]$Alignment)
    if ($Alignment -eq 0) {
        throw "Invalid zero alignment."
    }
    return [uint64]([Math]::Ceiling([double]$Value / [double]$Alignment) * $Alignment)
}

function Set-Rel32 {
    param(
        [byte[]]$Code,
        [int]$DisplacementOffset,
        [uint32]$InstructionEndRva,
        [uint32]$TargetRva
    )
    $delta = [int64]$TargetRva - [int64]$InstructionEndRva
    if ($delta -lt [int32]::MinValue -or $delta -gt [int32]::MaxValue) {
        throw "Callback target is outside x64 RIP-relative range."
    }
    [BitConverter]::GetBytes([int32]$delta).CopyTo($Code, $DisplacementOffset)
}

$resolvedPath = (Resolve-Path -LiteralPath $Path).Path
$inputBytes = [IO.File]::ReadAllBytes($resolvedPath)
if ($inputBytes.Length -lt 512 -or
    (Read-U16 $inputBytes 0) -ne 0x5A4D) {
    throw "Input is not a valid PE image."
}

$peOffset = [int](Read-U32 $inputBytes 0x3C)
if ($peOffset -lt 0 -or $peOffset + 24 -gt $inputBytes.Length -or
    (Read-U32 $inputBytes $peOffset) -ne 0x00004550) {
    throw "PE signature is absent or outside the file."
}

$machine = Read-U16 $inputBytes ($peOffset + 4)
$sectionCount = Read-U16 $inputBytes ($peOffset + 6)
$optionalSize = Read-U16 $inputBytes ($peOffset + 20)
$optionalOffset = $peOffset + 24
if ($sectionCount -eq 0 -or $optionalSize -lt 152 -or
    $optionalOffset + $optionalSize -gt $inputBytes.Length) {
    throw "PE optional header or section count is invalid."
}

if ($machine -ne 0x8664 -or
    (Read-U16 $inputBytes $optionalOffset) -ne 0x020B) {
    throw "PostProcessInitRoutine fixture patching supports only PE32+ x64."
}

$sectionAlignment = Read-U32 $inputBytes ($optionalOffset + 32)
$fileAlignment = Read-U32 $inputBytes ($optionalOffset + 36)
$sizeOfHeaders = Read-U32 $inputBytes ($optionalOffset + 60)
$numberOfRvaAndSizes = Read-U32 $inputBytes ($optionalOffset + 108)
if ($sectionAlignment -eq 0 -or $fileAlignment -eq 0 -or
    $numberOfRvaAndSizes -lt 5) {
    throw "PE optional header is incomplete."
}

$securityDirectoryOffset = $optionalOffset + 112 + (4 * 8)
if ((Read-U32 $inputBytes $securityDirectoryOffset) -ne 0 -or
    (Read-U32 $inputBytes ($securityDirectoryOffset + 4)) -ne 0) {
    throw "Refusing to modify an Authenticode-signed image."
}

$sectionTableOffset = $optionalOffset + $optionalSize
$newSectionHeaderOffset = $sectionTableOffset + ($sectionCount * 40)
if ($sectionTableOffset + ($sectionCount * 40) -gt $inputBytes.Length) {
    throw "PE section table extends outside the file."
}

if ($newSectionHeaderOffset + 40 -gt $sizeOfHeaders -or
    $newSectionHeaderOffset + 40 -gt $inputBytes.Length) {
    throw "PE headers do not have room for another section header."
}

$stateRva = $null
$maxVirtualEnd = [uint64]0
for ($index = 0; $index -lt $sectionCount; ++$index) {
    $sectionOffset = $sectionTableOffset + ($index * 40)
    $name = [Text.Encoding]::ASCII.GetString($inputBytes, $sectionOffset, 8).TrimEnd([char]0)
    if ($name -eq ".ppir") {
        throw "Image already contains a .ppir section."
    }

    $virtualSize = Read-U32 $inputBytes ($sectionOffset + 8)
    $virtualAddress = Read-U32 $inputBytes ($sectionOffset + 12)
    $rawSize = Read-U32 $inputBytes ($sectionOffset + 16)
    $rawOffset = Read-U32 $inputBytes ($sectionOffset + 20)
    $virtualEnd = [uint64]$virtualAddress + [Math]::Max([uint64]$virtualSize, [uint64]$rawSize)
    if ($virtualEnd -gt $maxVirtualEnd) {
        $maxVirtualEnd = $virtualEnd
    }

    if ($name -ne ".ppird") {
        continue
    }
    if ($rawSize -lt 12) {
        continue
    }
    if ([uint64]$rawOffset + [uint64]$rawSize -gt [uint64]$inputBytes.Length) {
        throw ".ppird raw data extends outside the file."
    }

    $signature = [byte[]](0x50, 0x50, 0x50, 0x31)
    for ($cursor = [int]$rawOffset;
         $cursor -le [int]($rawOffset + $rawSize - 12);
         ++$cursor) {
        if ($inputBytes[$cursor] -eq $signature[0] -and
            $inputBytes[$cursor + 1] -eq $signature[1] -and
            $inputBytes[$cursor + 2] -eq $signature[2] -and
            $inputBytes[$cursor + 3] -eq $signature[3]) {
            if ($null -ne $stateRva) {
                throw "Multiple prepatched state signatures found in .ppird."
            }
            $stateRva = [uint32]($virtualAddress + ($cursor - $rawOffset) + 4)
        }
    }
}

if ($null -eq $stateRva) {
    throw "Unique prepatched state signature was not found in .ppird."
}
$releaseRva = [uint32]($stateRva + 4)
$alignedVirtualAddress = Align-Up $maxVirtualEnd $sectionAlignment
if ($alignedVirtualAddress -gt [uint32]::MaxValue) {
    throw "New PE section virtual address would overflow."
}
$newVirtualAddress = [uint32]$alignedVirtualAddress

[byte[]]$routine = @(
    0xC7, 0x05, 0,    0,    0,    0,    0x45, 0x4E, 0x54, 0x52,
    0xB9, 0x80, 0x96, 0x98, 0x00,
    0x83, 0x3D, 0,    0,    0,    0,    0x00,
    0x75, 0x0F,
    0xF3, 0x90,
    0xE2, 0xF3,
    0xC7, 0x05, 0,    0,    0,    0,    0x54, 0x4F, 0x55, 0x54,
    0xC3,
    0xC7, 0x05, 0,    0,    0,    0,    0x44, 0x4F, 0x4E, 0x45,
    0xC3
)
Set-Rel32 $routine 2 ([uint32]($newVirtualAddress + 10)) $stateRva
Set-Rel32 $routine 17 ([uint32]($newVirtualAddress + 22)) $releaseRva
Set-Rel32 $routine 30 ([uint32]($newVirtualAddress + 38)) $stateRva
Set-Rel32 $routine 41 ([uint32]($newVirtualAddress + 49)) $stateRva

$newRawOffset = [uint32](Align-Up ([uint64]$inputBytes.Length) $fileAlignment)
$newRawSize = [uint32](Align-Up ([uint64]$routine.Length) $fileAlignment)
$newFileSize = [uint64]$newRawOffset + [uint64]$newRawSize
if ($newFileSize -gt [int]::MaxValue) {
    throw "Patched image would exceed supported size."
}

$outputBytes = New-Object byte[] ([int]$newFileSize)
[Array]::Copy($inputBytes, 0, $outputBytes, 0, $inputBytes.Length)
[Array]::Copy($routine, 0, $outputBytes, $newRawOffset, $routine.Length)

$nameBytes = [Text.Encoding]::ASCII.GetBytes(".ppir")
[Array]::Copy($nameBytes, 0, $outputBytes, $newSectionHeaderOffset, $nameBytes.Length)
Write-U32 $outputBytes ($newSectionHeaderOffset + 8) ([uint32]$routine.Length)
Write-U32 $outputBytes ($newSectionHeaderOffset + 12) $newVirtualAddress
Write-U32 $outputBytes ($newSectionHeaderOffset + 16) $newRawSize
Write-U32 $outputBytes ($newSectionHeaderOffset + 20) $newRawOffset
Write-U32 $outputBytes ($newSectionHeaderOffset + 36) ([uint32]0x60000020)

Write-U16 $outputBytes ($peOffset + 6) ([uint16]($sectionCount + 1))
$newSizeOfImage = [uint32](Align-Up ([uint64]$newVirtualAddress + [uint64]$routine.Length) $sectionAlignment)
Write-U32 $outputBytes ($optionalOffset + 56) $newSizeOfImage
$oldSizeOfCode = Read-U32 $inputBytes ($optionalOffset + 4)
if ([uint64]$oldSizeOfCode + [uint64]$newRawSize -gt [uint32]::MaxValue) {
    throw "PE SizeOfCode would overflow."
}
Write-U32 $outputBytes ($optionalOffset + 4) ([uint32]($oldSizeOfCode + $newRawSize))
Write-U32 $outputBytes ($optionalOffset + 64) 0

$tempPath = "$resolvedPath.ppir-$PID.tmp"
try {
    [IO.File]::WriteAllBytes($tempPath, $outputBytes)
    Move-Item -LiteralPath $tempPath -Destination $resolvedPath -Force
}
finally {
    if (Test-Path -LiteralPath $tempPath) {
        Remove-Item -LiteralPath $tempPath -Force
    }
}

Write-Host ("[BKAES] embedded .ppir callback RVA=0x{0:X8} state=0x{1:X8} release=0x{2:X8}" -f
    $newVirtualAddress, $stateRva, $releaseRva)

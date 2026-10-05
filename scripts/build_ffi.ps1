#!/usr/bin/env pwsh
# Build psa-ffi release shared library and copy into language packages.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host "Building psa-ffi (release)..."
cargo +stable-x86_64-pc-windows-gnu build -p psa-ffi --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$dll = Join-Path $Root "target\release\psa_ffi.dll"
$lib = Join-Path $Root "target\release\psa_ffi.dll.a"
if (-not (Test-Path $dll)) {
    # MSVC layout
    $dll = Join-Path $Root "target\release\psa_ffi.dll"
}
if (-not (Test-Path $dll)) {
    Write-Error "psa_ffi.dll not found under target/release"
}

$dests = @(
    "packages\psa-python\password_security_analyzer\lib",
    "packages\psa-go\lib",
    "packages\psa-java\src\main\resources\native",
    "packages\psa-node\lib",
    "packages\psa-dotnet\lib",
    "packages\psa-cpp\lib",
    "packages\psa-ruby\lib\native"
)

foreach ($d in $dests) {
    $full = Join-Path $Root $d
    New-Item -ItemType Directory -Force -Path $full | Out-Null
    Copy-Item $dll (Join-Path $full "psa_ffi.dll") -Force
    # MinGW/cgo import libraries (GNU layout)
    foreach ($implib in @(
        (Join-Path $Root "target\release\libpsa_ffi.dll.a"),
        (Join-Path $Root "target\release\psa_ffi.dll.a"),
        (Join-Path $Root "target\release\libpsa_ffi.a")
    )) {
        if (Test-Path $implib) {
            $base = Split-Path $implib -Leaf
            Copy-Item $implib (Join-Path $full $base) -Force
            if ($base -eq "libpsa_ffi.dll.a") {
                Copy-Item $implib (Join-Path $full "libpsa_ffi.a") -Force
            }
        }
    }
    Write-Host "Copied psa_ffi.dll -> $d"
}

# Header for Go/cgo/C++ consumers
$inc = Join-Path $Root "include\psa.h"
Copy-Item $inc (Join-Path $Root "packages\psa-go\psa.h") -Force
Copy-Item $inc (Join-Path $Root "packages\psa-java\psa.h") -Force
New-Item -ItemType Directory -Force -Path (Join-Path $Root "packages\psa-cpp\include") | Out-Null
Copy-Item $inc (Join-Path $Root "packages\psa-cpp\include\psa.h") -Force

Write-Host "Done."

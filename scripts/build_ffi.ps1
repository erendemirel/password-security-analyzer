#!/usr/bin/env pwsh
# Build psa-ffi release shared library and copy into language packages.
# Set PSA_FFI_COPY_STATIC=1 to also copy MinGW import/static libs (local cgo/C++).
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$CopyStatic = $env:PSA_FFI_COPY_STATIC -eq "1"

Write-Host "Building psa-ffi (release)..."
cargo +stable-x86_64-pc-windows-gnu build -p psa-ffi --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$dll = Join-Path $Root "target\release\psa_ffi.dll"
if (-not (Test-Path $dll)) {
    Write-Error "psa_ffi.dll not found under target/release"
}

$dests = @(
    "packages\psa-python\password_security_analyzer\lib",
    "packages\psa-go\lib\windows_amd64",
    "packages\psa-java\src\main\resources\native\windows-x86_64",
    "packages\psa-node\lib",
    "packages\psa-dotnet\runtimes\win-x64\native",
    "packages\psa-dotnet\lib",
    "packages\psa-cpp\lib",
    "packages\psa-ruby\lib\native\windows_amd64"
)

foreach ($d in $dests) {
    $full = Join-Path $Root $d
    New-Item -ItemType Directory -Force -Path $full | Out-Null
    Copy-Item $dll (Join-Path $full "psa_ffi.dll") -Force
    if ($CopyStatic) {
        foreach ($implib in @(
            (Join-Path $Root "target\release\libpsa_ffi.dll.a"),
            (Join-Path $Root "target\release\psa_ffi.dll.a")
        )) {
            if (Test-Path $implib) {
                Copy-Item $implib (Join-Path $full (Split-Path $implib -Leaf)) -Force
                if ((Split-Path $implib -Leaf) -eq "libpsa_ffi.dll.a") {
                    # Tiny import lib for cgo/MinGW — not the 46MB static archive
                    Copy-Item $implib (Join-Path $full "libpsa_ffi.dll.a") -Force
                }
            }
        }
    }
    # Always copy small import lib into Go windows folder for cgo
    if ($d -match "psa-go\\lib\\windows") {
        $imp = Join-Path $Root "target\release\libpsa_ffi.dll.a"
        if (Test-Path $imp) {
            Copy-Item $imp (Join-Path $full "libpsa_ffi.dll.a") -Force
        }
    }
    Write-Host "Copied psa_ffi.dll -> $d"
}

$inc = Join-Path $Root "include\psa.h"
Copy-Item $inc (Join-Path $Root "packages\psa-go\psa.h") -Force
Copy-Item $inc (Join-Path $Root "packages\psa-java\psa.h") -Force
New-Item -ItemType Directory -Force -Path (Join-Path $Root "packages\psa-cpp\include") | Out-Null
Copy-Item $inc (Join-Path $Root "packages\psa-cpp\include\psa.h") -Force

Write-Host "Done."

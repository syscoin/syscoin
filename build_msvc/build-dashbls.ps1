# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [switch]$RunTests
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$SourcePath = Join-Path $RepoRoot "src\dashbls"
$BuildPath = Join-Path $PSScriptRoot "dashbls-build"
$InstallPath = Join-Path $PSScriptRoot "dashbls-install"
$BuildTests = if ($RunTests) { "ON" } else { "OFF" }
$RelicConfigTemplate = Join-Path $PSScriptRoot "dashbls-relic-conf.h.in"
$RelicConfigTarget = Join-Path $SourcePath "depends\relic\include\relic_conf.h.in"

# The autotools build generates this file with autoheader, while Relic's CMake
# build needs its own @VAR@/#cmakedefine template. Keep the CMake version in the
# MSVC build directory so running autogen.sh does not dirty a tracked file.
Copy-Item -Path $RelicConfigTemplate -Destination $RelicConfigTarget -Force

# Relic's OpenMP threadprivate declarations are not accepted by MSVC. The
# native CI build does not require internal Relic parallelism.
$ConfigureArgs = @(
    "-S", $SourcePath,
    "-B", $BuildPath,
    "-G", "Visual Studio 17 2022",
    "-A", "x64",
    "-DCMAKE_BUILD_TYPE=$Configuration",
    "-DCMAKE_INSTALL_PREFIX=$InstallPath",
    "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
    "-DCMAKE_POLICY_DEFAULT_CMP0091=NEW",
    '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>',
    "-DRUNTIME=MT",
    "-DARITH=easy",
    "-DMULTI=",
    "-DBUILD_BLS_JS_BINDINGS=OFF",
    "-DBUILD_BLS_PYTHON_BINDINGS=OFF",
    "-DBUILD_BLS_TESTS=$BuildTests",
    "-DBUILD_BLS_BENCHMARKS=OFF",
    "-DMI_BUILD_SHARED=OFF",
    "-DMI_BUILD_OBJECT=OFF",
    "-DMI_INSTALL_TOPLEVEL=ON"
)

& cmake @ConfigureArgs
if ($LASTEXITCODE -ne 0) {
    throw "Dash BLS configuration failed with exit code $LASTEXITCODE"
}

$BuildTargets = @("dashbls")
if ($RunTests) {
    $BuildTargets += "runtest"
}

& cmake --build $BuildPath --config $Configuration --target @BuildTargets --parallel
if ($LASTEXITCODE -ne 0) {
    throw "Dash BLS build failed with exit code $LASTEXITCODE"
}

& cmake --install $BuildPath --config $Configuration
if ($LASTEXITCODE -ne 0) {
    throw "Dash BLS installation failed with exit code $LASTEXITCODE"
}

$MimallocLibrary = if ($Configuration -eq "Debug") {
    "mimalloc-static-secure-debug.lib"
} else {
    "mimalloc-static-secure.lib"
}
$ExpectedLibraries = @(
    "dashbls.lib",
    "relic_s.lib",
    $MimallocLibrary
)
foreach ($Library in $ExpectedLibraries) {
    $LibraryPath = Join-Path $InstallPath "lib\$Library"
    if (-not (Test-Path $LibraryPath)) {
        throw "Expected Dash BLS dependency was not installed: $LibraryPath"
    }
}

if ($RunTests) {
    $TestPath = Join-Path $BuildPath "src\$Configuration\runtest.exe"
    if (-not (Test-Path $TestPath)) {
        throw "Dash BLS test executable was not built: $TestPath"
    }
    & $TestPath
    if ($LASTEXITCODE -ne 0) {
        throw "Dash BLS tests failed with exit code $LASTEXITCODE"
    }
}

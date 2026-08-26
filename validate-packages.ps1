# Package Validation Script (PowerShell)
# Validates all packages before publishing

param(
    [switch]$SkipBuilds
)

$ErrorActionPreference = "Continue"

function PrintError {
    param([string]$Message)
    Write-Host "  [X] $Message" -ForegroundColor Red
    $script:Errors++
}

function PrintOk {
    param([string]$Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function PrintWarn {
    param([string]$Message)
    Write-Host "  [WARN] $Message" -ForegroundColor Yellow
}

function PrintHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host ""
}

function Confirm-Python {
    $hasError = $false
    Push-Location $Root\python
    try {
        if (-not (Test-Path "pyproject.toml")) { PrintError "pyproject.toml missing"; $hasError = $true }
        else { PrintOk "pyproject.toml found" }

        if (-not (Test-Path "README.md")) { PrintError "README.md missing"; $hasError = $true }
        else { PrintOk "README.md found" }

        if (-not (Test-Path "LICENSE")) { PrintError "LICENSE missing"; $hasError = $true }
        else { PrintOk "LICENSE found" }

        if (-not (Test-Path "CHANGELOG.md")) { PrintWarn "CHANGELOG.md missing"; $hasError = $true }
        else { PrintOk "CHANGELOG.md found" }

        python -m pytest test_auth_framework.py -v --tb=short
        if ($LASTEXITCODE -ne 0) { throw "pytest failed" }
        PrintOk "Python tests passed"

        if (-not $SkipBuilds) {
            python -m build
            if ($LASTEXITCODE -ne 0) { throw "python build failed" }
            PrintOk "Python package built"
        }
    }
    catch {
        PrintError "Python validation failed: $_"
        $hasError = $true
    }
    finally {
        Pop-Location
    }

    if ($hasError) { $script:SectionsFailed++ }
    else { $script:SectionsPassed++ }
}

function Confirm-TypeScript {
    $hasError = $false
    Push-Location $Root\typescript
    try {
        if (-not (Test-Path "package.json")) { PrintError "package.json missing"; $hasError = $true }
        else { PrintOk "package.json found" }

        if (-not (Test-Path "README.md")) { PrintError "README.md missing"; $hasError = $true }
        else { PrintOk "README.md found" }

        if (-not (Test-Path "LICENSE")) { PrintError "LICENSE missing"; $hasError = $true }
        else { PrintOk "LICENSE found" }

        if (-not (Test-Path "CHANGELOG.md")) { PrintWarn "CHANGELOG.md missing"; $hasError = $true }
        else { PrintOk "CHANGELOG.md found" }

        npm ci 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }

        npm test 2>&1
        if ($LASTEXITCODE -ne 0) { throw "npm test failed" }
        PrintOk "TypeScript tests passed"

        if (-not $SkipBuilds) {
            npm run build 2>&1
            if ($LASTEXITCODE -ne 0) { throw "npm run build failed" }
            if ((Test-Path "dist\index.js") -and (Test-Path "dist\index.d.ts")) {
                PrintOk "TypeScript package built"
            }
            else {
                throw "TypeScript build output missing"
            }
        }
    }
    catch {
        PrintError "TypeScript validation failed: $_"
        $hasError = $true
    }
    finally {
        Pop-Location
    }

    if ($hasError) { $script:SectionsFailed++ }
    else { $script:SectionsPassed++ }
}

function Confirm-Go {
    $hasError = $false
    Push-Location $Root\go
    try {
        if (-not (Test-Path "go.mod")) { PrintError "go.mod missing"; $hasError = $true }
        else { PrintOk "go.mod found" }

        if (-not (Test-Path "README.md")) { PrintError "README.md missing"; $hasError = $true }
        else { PrintOk "README.md found" }

        if (-not (Test-Path "LICENSE")) { PrintError "LICENSE missing"; $hasError = $true }
        else { PrintOk "LICENSE found" }

        if (-not (Test-Path "CHANGELOG.md")) { PrintWarn "CHANGELOG.md missing"; $hasError = $true }
        else { PrintOk "CHANGELOG.md found" }

        if (-not (Test-Path "doc.go")) { PrintWarn "doc.go missing (recommended for pkg.go.dev)" }
        else { PrintOk "doc.go found" }

        go mod download
        if ($LASTEXITCODE -ne 0) { throw "go mod download failed" }

        go test -v .\...
        if ($LASTEXITCODE -ne 0) { throw "go test failed" }
        PrintOk "Go tests passed"

        go build -v .\...
        if ($LASTEXITCODE -ne 0) { throw "go build failed" }
        PrintOk "Go build succeeded"
    }
    catch {
        PrintError "Go validation failed: $_"
        $hasError = $true
    }
    finally {
        Pop-Location
    }

    if ($hasError) { $script:SectionsFailed++ }
    else { $script:SectionsPassed++ }
}

# ============================================================================
# Main
# ============================================================================

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:Errors = 0
$script:SectionsPassed = 0
$script:SectionsFailed = 0

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Auth Framework - Package Validation" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

Confirm-Python
Confirm-TypeScript
Confirm-Go

PrintHeader -Title "Validation Summary"

Write-Host "Sections passed: $script:SectionsPassed" -ForegroundColor Green
Write-Host "Sections failed: $script:SectionsFailed" -ForegroundColor Red
Write-Host "Total errors: $script:Errors" -ForegroundColor Red
Write-Host ""

if ($script:Errors -ne 0) {
    Write-Host "=========================================" -ForegroundColor Red
    Write-Host "[X] VALIDATION FAILED" -ForegroundColor Red
    Write-Host "=========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please fix the errors above before publishing."
    Write-Host ""
    exit 1
}

Write-Host "=========================================" -ForegroundColor Green
Write-Host "[OK] ALL VALIDATIONS PASSED" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Packages are ready for publishing."
Write-Host "Next: review CHANGELOG, commit, and tag v1.0.0"
Write-Host ""
exit 0

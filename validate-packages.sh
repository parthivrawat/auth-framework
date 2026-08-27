#!/bin/bash

# Package Validation Script
# Validates all packages before publishing

set -e

echo "========================================="
echo "Auth Framework - Package Validation"
echo "========================================="
echo ""

ERRORS=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
error() {
    echo -e "${RED}✗ $1${NC}"
    ERRORS=$((ERRORS + 1))
}

success() {
    echo -e "${GREEN}✓ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

section() {
    echo ""
    echo "========================================="
    echo "$1"
    echo "========================================="
}

# ============================================================================
# Python Validation
# ============================================================================

section "Validating Python Package"

cd python

# Check pyproject.toml exists
if [ ! -f "pyproject.toml" ]; then
    error "pyproject.toml not found"
else
    success "pyproject.toml found"
fi

# Check version
PYTHON_VERSION=$(grep '^version = ' pyproject.toml | cut -d'"' -f2)
if [ -z "$PYTHON_VERSION" ]; then
    error "Python version not found in pyproject.toml"
else
    success "Python version: $PYTHON_VERSION"
fi

# Check README
if [ ! -f "README.md" ]; then
    error "README.md not found"
else
    success "README.md found"
fi

# Check LICENSE
if [ ! -f "LICENSE" ]; then
    error "LICENSE not found"
else
    success "LICENSE found"
fi

# Check CHANGELOG
if [ ! -f "CHANGELOG.md" ]; then
    warning "CHANGELOG.md not found (recommended)"
else
    success "CHANGELOG.md found"
fi

# Run tests
echo ""
echo "Running Python tests..."
if python -m pytest test_auth_framework.py -v --tb=short; then
    success "All Python tests passed"
else
    error "Python tests failed"
fi

# Build package
echo ""
echo "Building Python package..."
if python -m build; then
    success "Python package built successfully"
    
    # Check dist files
    if [ -f "dist/auth_framework_py-${PYTHON_VERSION}.tar.gz" ]; then
        success "Source distribution created"
    else
        warning "Source distribution not found"
    fi
    
    if ls dist/auth_framework_py-${PYTHON_VERSION}-*.whl 1> /dev/null 2>&1; then
        success "Wheel distribution created"
    else
        warning "Wheel distribution not found"
    fi
else
    error "Python package build failed"
fi

# Check package with twine
echo ""
echo "Checking Python package..."
if python -m twine check dist/*; then
    success "Package check passed"
else
    error "Package check failed"
fi

cd ..

# ============================================================================
# TypeScript Validation
# ============================================================================

section "Validating TypeScript Package"

cd typescript

# Check package.json exists
if [ ! -f "package.json" ]; then
    error "package.json not found"
else
    success "package.json found"
fi

# Check version
TS_VERSION=$(node -p "require('./package.json').version")
if [ -z "$TS_VERSION" ]; then
    error "TypeScript version not found in package.json"
else
    success "TypeScript version: $TS_VERSION"
fi

# Check version consistency
if [ "$PYTHON_VERSION" != "$TS_VERSION" ]; then
    error "Version mismatch: Python=$PYTHON_VERSION, TypeScript=$TS_VERSION"
else
    success "Versions match across languages"
fi

# Check README
if [ ! -f "README.md" ]; then
    error "README.md not found"
else
    success "README.md found"
fi

# Check LICENSE
if [ ! -f "LICENSE" ]; then
    error "LICENSE not found"
else
    success "LICENSE found"
fi

# Check CHANGELOG
if [ ! -f "CHANGELOG.md" ]; then
    warning "CHANGELOG.md not found (recommended)"
else
    success "CHANGELOG.md found"
fi

# Install dependencies
echo ""
echo "Installing TypeScript dependencies..."
if npm ci; then
    success "Dependencies installed"
else
    error "Dependency installation failed"
fi

# Run tests
echo ""
echo "Running TypeScript tests..."
if npm test; then
    success "All TypeScript tests passed"
else
    error "TypeScript tests failed"
fi

# Build package
echo ""
echo "Building TypeScript package..."
if npm run build; then
    success "TypeScript package built successfully"
    
    # Check dist files
    if [ -f "dist/index.js" ]; then
        success "JavaScript output created"
    else
        error "JavaScript output not found"
    fi
    
    if [ -f "dist/index.d.ts" ]; then
        success "Type definitions created"
    else
        error "Type definitions not found"
    fi
else
    error "TypeScript package build failed"
fi

# Type check
echo ""
echo "Running type check..."
if npm run lint; then
    success "Type check passed"
else
    error "Type check failed"
fi

# Create tarball for testing
echo ""
echo "Creating NPM tarball..."
if npm pack; then
    success "NPM tarball created"
else
    error "NPM tarball creation failed"
fi

cd ..

# ============================================================================
# Go Validation
# ============================================================================

section "Validating Go Module"

cd go

# Check go.mod exists
if [ ! -f "go.mod" ]; then
    error "go.mod not found"
else
    success "go.mod found"
fi

# Check module path
MODULE_PATH=$(grep '^module ' go.mod | awk '{print $2}')
if [ "$MODULE_PATH" != "github.com/parthivrawat/auth-framework/go" ]; then
    error "Incorrect module path: $MODULE_PATH"
else
    success "Module path correct: $MODULE_PATH"
fi

# Check README
if [ ! -f "README.md" ]; then
    error "README.md not found"
else
    success "README.md found"
fi

# Check LICENSE
if [ ! -f "LICENSE" ]; then
    error "LICENSE not found"
else
    success "LICENSE found"
fi

# Check CHANGELOG
if [ ! -f "CHANGELOG.md" ]; then
    warning "CHANGELOG.md not found (recommended)"
else
    success "CHANGELOG.md found"
fi

# Check doc.go
if [ ! -f "doc.go" ]; then
    warning "doc.go not found (recommended for pkg.go.dev)"
else
    success "doc.go found"
fi

# Download dependencies
echo ""
echo "Downloading Go dependencies..."
if go mod download; then
    success "Dependencies downloaded"
else
    error "Dependency download failed"
fi

# Verify dependencies
echo ""
echo "Verifying Go dependencies..."
if go mod verify; then
    success "Dependencies verified"
else
    error "Dependency verification failed"
fi

# Run tests
echo ""
echo "Running Go tests..."
if go test -v ./...; then
    success "All Go tests passed"
else
    error "Go tests failed"
fi

# Run tests with race detector
echo ""
echo "Running Go tests with race detector..."
if go test -race ./...; then
    success "Race detector tests passed"
else
    error "Race detector tests failed"
fi

# Check formatting
echo ""
echo "Checking Go formatting..."
UNFORMATTED=$(gofmt -l .)
if [ -z "$UNFORMATTED" ]; then
    success "All files properly formatted"
else
    error "Unformatted files found: $UNFORMATTED"
fi

# Run go vet
echo ""
echo "Running go vet..."
if go vet ./...; then
    success "go vet passed"
else
    error "go vet failed"
fi

# Build
echo ""
echo "Building Go package..."
if go build -v ./...; then
    success "Go package built successfully"
else
    error "Go package build failed"
fi

cd ..

# ============================================================================
# Summary
# ============================================================================

section "Validation Summary"

echo ""
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}✓ All validations passed!${NC}"
    echo -e "${GREEN}=========================================${NC}"
    echo ""
    echo "Packages are ready for publishing:"
    echo "  - Python: $PYTHON_VERSION"
    echo "  - TypeScript: $TS_VERSION"
    echo "  - Go: (use git tag v$PYTHON_VERSION)"
    echo ""
    echo "Next steps:"
    echo "  1. Review CHANGELOG.md in each package"
    echo "  2. Commit all changes"
    echo "  3. Create git tag: git tag v$PYTHON_VERSION"
    echo "  4. Push tag: git push origin v$PYTHON_VERSION"
    echo "  5. GitHub Actions will automatically publish"
    echo ""
    exit 0
else
    echo -e "${RED}=========================================${NC}"
    echo -e "${RED}✗ Validation failed with $ERRORS error(s)${NC}"
    echo -e "${RED}=========================================${NC}"
    echo ""
    echo "Please fix the errors above before publishing."
    echo ""
    exit 1
fi

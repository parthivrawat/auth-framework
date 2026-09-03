# Maintainer Guide

Quick reference for maintaining and publishing the Auth & Authorization Framework.

---

## 🚀 Quick Start for Maintainers

### Daily Development

```bash
# Run all tests
cd python && pytest test_auth_framework.py -v
cd ../typescript && npm test
cd ../go && go test -v ./...
cd ../rust && cargo test

# Validate packages before committing
./validate-packages.sh  # Linux/macOS
.\validate-packages.ps1 # Windows
```

---

## 📦 Publishing a New Version

### 1. Prepare Release

```bash
# Update version in all package files
# - python/pyproject.toml
# - typescript/package.json
# - rust/Cargo.toml
# (Go uses git tags only)

# Update CHANGELOGs
# - python/CHANGELOG.md
# - typescript/CHANGELOG.md
# - go/CHANGELOG.md
# - rust/CHANGELOG.md
```

### 2. Validate

```bash
# Run validation script
./validate-packages.sh

# Expected output: "All validations passed!"
```

### 3. Commit and Tag

```bash
# Commit changes
git add .
git commit -m "Release v1.0.3"

# Create and push the main release tag
git tag v1.0.3
git push origin main
git push origin v1.0.3

# Create and push the Go submodule tag
git tag go/v1.0.3
git push origin go/v1.0.3
```

### 4. Automated Publishing

GitHub Actions will automatically:
- ✅ Run all tests
- ✅ Validate versions
- ✅ Publish to PyPI
- ✅ Publish to NPM
- ✅ Publish to crates.io
- ✅ Index on pkg.go.dev
- ✅ Create GitHub release

### 5. Verify

```bash
# Check PyPI
pip install auth-framework-py==1.0.3

# Check NPM
npm info @prthv-rwt/auth-framework@1.0.3

# Check pkg.go.dev
go get github.com/parthivrawat/auth-framework/go@v1.0.3

# Check crates.io
cargo install auth-framework-rs --version 1.0.3
```

---

## 🔧 Common Tasks

### Adding a New Feature

1. **Write tests first** (TDD)
2. **Implement in all four languages** (Python, TypeScript, Go, Rust)
3. **Update documentation**
4. **Run validation**
5. **Create PR**

### Fixing a Bug

1. **Add regression test**
2. **Fix in all affected languages**
3. **Verify fix with tests**
4. **Update CHANGELOG**
5. **Patch version bump**

### Breaking Change

1. **Document migration path**
2. **Update all examples**
3. **Major version bump**
4. **Create migration guide**

---

## 📋 Checklists

### Pre-Release Checklist

- [ ] All tests passing (110/110)
- [ ] Version bumped in all files
- [ ] CHANGELOG updated
- [ ] Documentation updated
- [ ] Examples tested
- [ ] Validation script passed
- [ ] No security vulnerabilities
- [ ] Performance benchmarks run

### Post-Release Checklist

- [ ] Packages verified on registries
- [ ] Installation tested from registries
- [ ] GitHub release created
- [ ] Documentation website updated
- [ ] Community notified
- [ ] Monitoring enabled

---

## 🐛 Troubleshooting

### Tests Failing

```bash
# Python
cd python
pytest test_auth_framework.py -v --tb=long

# TypeScript
cd typescript
npm test -- --reporter=verbose

# Go
cd go
go test -v -race ./...

# Rust
cd rust
cargo test -- --nocapture
```

### Build Failing

```bash
# Python
cd python
python -m build --verbose

# TypeScript
cd typescript
npm run build -- --verbose

# Go
cd go
go build -v ./...

# Rust
cd rust
cargo build -v
```

### Publishing Failing

Check GitHub Actions logs:
- https://github.com/parthivrawat/auth-framework/actions

Common issues:
- **PyPI**: Invalid API token → Update `PYPI_API_TOKEN` secret
- **NPM**: Invalid token → Update `NPM_TOKEN` secret
- **Go**: Module path mismatch → Check `go.mod`

---

## 📊 Monitoring

### Package Statistics

- **PyPI**: https://pypistats.org/packages/auth-framework-py
- **NPM**: https://www.npmjs.com/package/@prthv-rwt/auth-framework
- **crates.io**: https://crates.io/crates/auth-framework-rs
- **Go**: https://pkg.go.dev/github.com/parthivrawat/auth-framework/go?tab=importedby

### Issue Tracking

- **GitHub Issues**: https://github.com/parthivrawat/auth-framework/issues
- **Security**: Use GitHub Security Advisories

---

## 🔐 Security

### Reporting Vulnerabilities

Email: security@example.com

Do not open public issues for security vulnerabilities.

### Updating Dependencies

```bash
# Python
cd python
pip list --outdated
pip install -U package-name

# TypeScript
cd typescript
npm outdated
npm update

# Go
cd go
go get -u ./...
go mod tidy

# Rust
cd rust
cargo update
```

---

## 📚 Resources

- **Publishing Guide**: `PUBLISHING.md`
- **Standardization Summary**: `PACKAGE_STANDARDIZATION.md`
- **Implementation Status**: `IMPLEMENTATION_STATUS.md`
- **Main README**: `README.md`

---

## 🤝 Community

### Responding to Issues

1. **Acknowledge** within 24 hours
2. **Reproduce** the issue
3. **Label** appropriately (bug, feature, question)
4. **Assign** if working on it
5. **Close** with resolution

### Reviewing PRs

1. **Check tests** pass
2. **Review code** quality
3. **Verify documentation** updated
4. **Run locally** if needed
5. **Request changes** or approve

---

## 📈 Metrics to Track

- Download counts (PyPI, NPM)
- GitHub stars
- Open/closed issues
- PR merge time
- Test coverage
- Security vulnerabilities
- Community engagement

---

- **Last Updated**: 2026-09-03
- **Maintainers**: Parthiv Rawat
- **Contact**: parthiv05022000@gmail.com

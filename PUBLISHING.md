# Publishing Guide

This document describes how to publish the Auth & Authorization Framework to various package managers.

## Prerequisites

- [ ] All tests passing in all languages
- [ ] Version numbers updated in all package files
- [ ] CHANGELOG.md updated in all languages
- [ ] Documentation reviewed and updated
- [ ] Git repository tagged with version number

---

## Python - PyPI

### Prerequisites

```bash
pip install build twine
```

### Build

```bash
cd python
python -m build
```

This creates:
- `dist/auth_framework_py-1.0.0.tar.gz` (source distribution)
- `dist/auth_framework_py-1.0.0-py3-none-any.whl` (wheel)

### Test on TestPyPI (Recommended First)

```bash
# Upload to TestPyPI
python -m twine upload --repository testpypi dist/*

# Test installation
pip install --index-url https://test.pypi.org/simple/ auth-framework-py
```

### Publish to PyPI

```bash
# Upload to PyPI
python -m twine upload dist/*

# Verify
pip install auth-framework-py
```

### Using API Tokens (Recommended)

1. Create API token at https://pypi.org/manage/account/token/
2. Create `~/.pypirc`:

```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = pypi-YOUR-API-TOKEN-HERE

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-YOUR-TEST-API-TOKEN-HERE
```

### Automation

```bash
# One-command publish
cd python
rm -rf dist/
python -m build
python -m twine check dist/*
python -m twine upload dist/*
```

---

## TypeScript - NPM

### Prerequisites

```bash
npm login
```

### Build

```bash
cd typescript
npm run build
```

### Test Package Locally

```bash
# Create tarball
npm pack

# Test installation
npm install prthv-rwt-auth-framework-1.0.0.tgz
```

### Publish to NPM

```bash
# Dry run (see what will be published)
npm publish --dry-run

# Publish (scoped package, public access)
npm publish --access public

# Verify
npm info @prthv-rwt/auth-framework
```

### Using NPM Tokens

1. Create token at https://www.npmjs.com/settings/~/tokens
2. Set environment variable:

```bash
export NPM_TOKEN=your-token-here
```

Or create `~/.npmrc`:

```
//registry.npmjs.org/:_authToken=YOUR-NPM-TOKEN-HERE
```

### Automation

```bash
# One-command publish
cd typescript
npm run clean
npm run build
npm test
npm publish --access public
```

---

## Go - pkg.go.dev

Go modules are published by pushing tags to GitHub. No separate upload needed!

### Prerequisites

- Git repository must be public
- Module path must match repository URL

### Tag and Push

```bash
# From repository root
git tag go/v1.0.2
git push origin go/v1.0.2
```

### Trigger pkg.go.dev Indexing

Visit: https://pkg.go.dev/github.com/parthivrawat/auth-framework/go

Or use:

```bash
curl https://proxy.golang.org/github.com/parthivrawat/auth-framework/go/@v/v1.0.2.info
```

### Verify

```bash
# Test installation
go get github.com/parthivrawat/auth-framework/go@v1.0.2

# Check documentation
open https://pkg.go.dev/github.com/parthivrawat/auth-framework/go@v1.0.2
```

### Best Practices

1. Use semantic versioning (v1.0.0, v1.0.1, etc.)
2. Tag from main/master branch
3. Ensure go.mod is committed
4. Run `go mod tidy` before tagging
5. Include comprehensive godoc comments

---

## Version Management

### Semantic Versioning

Follow [SemVer](https://semver.org/):

- **MAJOR** (1.0.0 → 2.0.0): Breaking changes
- **MINOR** (1.0.0 → 1.1.0): New features, backward compatible
- **PATCH** (1.0.0 → 1.0.1): Bug fixes, backward compatible

### Update Version Numbers

Before publishing, update version in:

**Python:**
- `python/pyproject.toml` → `version = "1.0.1"`

**TypeScript:**
- `typescript/package.json` → `"version": "1.0.1"`

**Go:**
- Git tag only (no file changes needed)

### Update Changelogs

Add new version section to:
- `python/CHANGELOG.md`
- `typescript/CHANGELOG.md`
- `go/CHANGELOG.md`

---

## Pre-Release Checklist

- [ ] All tests passing (Python: 40, TypeScript: 38, Go: 14)
- [ ] Documentation updated
- [ ] CHANGELOG.md updated for all languages
- [ ] Version numbers bumped
- [ ] README examples tested
- [ ] Security audit completed
- [ ] Performance benchmarks run
- [ ] Breaking changes documented
- [ ] Migration guide written (if needed)

---

## Post-Release Checklist

- [ ] Git tag created and pushed
- [ ] GitHub release created with notes
- [ ] PyPI package published
- [ ] NPM package published
- [ ] pkg.go.dev indexed
- [ ] Documentation website updated
- [ ] Announcement posted (blog, Twitter, etc.)
- [ ] Community notified (Discord, Slack, etc.)

---

## Rollback Procedures

### PyPI

Cannot delete versions, but can yank them:

```bash
pip install twine
twine upload --repository pypi --skip-existing dist/*
# If needed:
# Visit https://pypi.org/project/auth-framework-py/ and yank version
```

### NPM

Can deprecate or unpublish (within 72 hours):

```bash
# Deprecate
npm deprecate @prthv-rwt/auth-framework@1.0.0 "This version has issues, use 1.0.1"

# Unpublish (within 72 hours only)
npm unpublish @prthv-rwt/auth-framework@1.0.0
```

### Go

Cannot delete tags from pkg.go.dev, but can:

1. Delete Git tag locally and remotely
2. Push new tag with +1 patch version
3. Document issue in CHANGELOG

---

## CI/CD Automation

### GitHub Actions Example

Create `.github/workflows/publish.yml`:

```yaml
name: Publish Packages

on:
  push:
    tags:
      - 'v*'

jobs:
  publish-python:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Build and publish
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
        run: |
          cd python
          pip install build twine
          python -m build
          twine upload dist/*

  publish-npm:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
          registry-url: 'https://registry.npmjs.org'
      - name: Build and publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: |
          cd typescript
          npm ci
          npm run build
          npm test
          npm publish --access public

  publish-go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      - name: Test
        run: |
          cd go
          go test -v ./...
      # Go publishing is automatic via git tags
```

---

## Support

For issues with publishing:

- **PyPI**: https://pypi.org/help/
- **NPM**: https://docs.npmjs.com/
- **Go**: https://go.dev/doc/modules/publishing

For package-specific issues:

- GitHub Issues: https://github.com/parthivrawat/auth-framework/issues
- Email: parthiv05022000@gmail.com

---

**Last Updated**: 2024-08-26  
**Current Version**: 1.0.0

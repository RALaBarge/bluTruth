# bluTruth Release & Packaging Guide

Complete guide to releasing bluTruth on PyPI and Homebrew.

---

## Table of Contents

1. [Pre-Release Checklist](#pre-release-checklist)
2. [PyPI Release](#pypi-release)
3. [Homebrew Release](#homebrew-release)
4. [Docker Release](#docker-release)
5. [Release Automation](#release-automation)
6. [Troubleshooting](#troubleshooting)

---

## Pre-Release Checklist

Before releasing, verify:

- [ ] All tests pass: `pytest` (100% coverage for critical paths)
- [ ] Code is linted: `black blutruth/` and `isort blutruth/`
- [ ] Type hints are valid: `mypy blutruth/`
- [ ] Dependencies are pinned: Check `pyproject.toml`
- [ ] Changelog is updated: `CHANGELOG.md` with version and date
- [ ] Version is bumped: `blutruth/__init__.py` (semantic versioning)
- [ ] Git tag is created: `git tag v0.X.Y`
- [ ] README is current: Links, examples, installation steps
- [ ] License is included: MIT license in `LICENSE` file
- [ ] Documentation builds: `sphinx build` (if using)

### Version Bumping

Edit `pyproject.toml`:

```toml
[project]
name = "blutruth"
version = "0.2.0"  # Increment here
```

Also update `blutruth/__init__.py`:

```python
__version__ = "0.2.0"
```

Update `CHANGELOG.md`:

```markdown
## [0.2.0] - 2026-04-12

### Added
- BlueTruthTool integration for BeigeBox agents
- Device simulation for testing without hardware
- Support for 15+ collector types

### Fixed
- SQLite write performance under heavy load
- Correlation engine race conditions

### Changed
- Event schema version 2 (backwards compatible)
```

---

## PyPI Release

### 1. Build Artifacts

```bash
# Install build dependencies
pip install build twine

# Clean old builds
rm -rf build/ dist/ *.egg-info

# Build wheel + source distribution
python -m build
```

Verify artifacts:

```bash
ls -lh dist/
# Should have:
#   - blutruth-0.2.0.tar.gz (source)
#   - blutruth-0.2.0-py3-none-any.whl (wheel)
```

### 2. Test Locally

```bash
# Create test venv
python -m venv /tmp/test_release
source /tmp/test_release/bin/activate

# Install from local wheel
pip install dist/blutruth-0.2.0-py3-none-any.whl

# Test CLI works
blutruth --help
blutruth --version  # Should print 0.2.0
```

### 3. Setup PyPI Credentials

Create `~/.pypirc`:

```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
repository = https://upload.pypi.org/legacy/
username = __token__
password = pypi-AgEIcHlwaS5vcmc...  # Your PyPI API token

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-AgEIcHlwaS5vcmc...  # Your TestPyPI API token
```

**Get API tokens:**
- PyPI: https://pypi.org/manage/account/tokens/
- TestPyPI: https://test.pypi.org/manage/account/tokens/

### 4. Upload to TestPyPI (Optional but Recommended)

```bash
twine upload --repository testpypi dist/*
```

Test installation:

```bash
pip install --index-url https://test.pypi.org/simple/ blutruth
```

### 5. Upload to Production PyPI

```bash
twine upload dist/*
```

Verify:

```bash
pip install blutruth
blutruth --version
```

**PyPI Package URL**: https://pypi.org/project/blutruth/

---

## Homebrew Release

### 1. Create Homebrew Formula

Create `HomebrewBlutruth.rb`:

```ruby
class Blutruth < Formula
  desc "Unified Bluetooth diagnostic platform"
  homepage "https://github.com/yourusername/blutruth"
  url "https://github.com/yourusername/blutruth/archive/v0.2.0.tar.gz"
  sha256 "abc123def456..."  # Run: shasum -a 256 blutruth-0.2.0.tar.gz
  license "MIT"

  depends_on "python@3.11"
  depends_on "dbus"

  def install
    venv = virtualenv_create(libexec, "python3.11")
    venv.pip_install_and_link buildpath

    # Optional: install shell completions
    bash_completion.install "completions/blutruth.bash"
    zsh_completion.install "completions/_blutruth"
  end

  test do
    system bin/"blutruth", "--version"
  end
end
```

### 2. Compute SHA256

```bash
# After uploading tarball to GitHub releases
curl -s https://github.com/yourusername/blutruth/archive/v0.2.0.tar.gz | shasum -a 256
# Output: abc123def456...
```

Update formula with this hash.

### 3. Test Locally

```bash
# Copy formula to Homebrew dir
cp HomebrewBlutruth.rb $(brew --repo homebrew/core)/Formula/blutruth.rb

# Or use homebrew-yourusername tap:
mkdir -p homebrew-blutruth/Formula
cp HomebrewBlutruth.rb homebrew-blutruth/Formula/blutruth.rb

# Test installation
brew install ./homebrew-blutruth/Formula/blutruth.rb --verbose

# Verify
blutruth --help
```

### 4. Create Homebrew Tap (Custom)

If you don't want to submit to official Homebrew, create your own tap:

```bash
# Create tap repo
mkdir -p homebrew-blutruth
cd homebrew-blutruth

# Initialize git
git init
git branch -M main

# Structure:
# homebrew-blutruth/
#   Formula/
#     blutruth.rb
#   README.md
#   LICENSE
```

Install from custom tap:

```bash
brew tap yourusername/blutruth https://github.com/yourusername/homebrew-blutruth
brew install blutruth
```

### 5. Submit to Official Homebrew (Optional)

For official Homebrew core:

1. Fork https://github.com/Homebrew/homebrew-core
2. Add formula to `Formula/blutruth.rb`
3. Test: `brew install ./Formula/blutruth.rb`
4. Submit PR with:
   - Formula
   - Test case (at least `--version`)
   - SHA256 hash
   - License file

Homebrew maintainers will review and merge.

---

## Docker Release

### 1. Build Docker Image

```bash
# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    dbus \
    btmon \
    bluetooth \
    bluez \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir -e .

EXPOSE 8484
ENTRYPOINT ["blutruth"]
CMD ["serve", "--host", "0.0.0.0"]
EOF
```

### 2. Build & Tag

```bash
docker build -t blutruth:0.2.0 .
docker tag blutruth:0.2.0 blutruth:latest
```

### 3. Push to Registry

```bash
# Docker Hub
docker tag blutruth:0.2.0 yourusername/blutruth:0.2.0
docker push yourusername/blutruth:0.2.0

# Or GitHub Container Registry
docker tag blutruth:0.2.0 ghcr.io/yourusername/blutruth:0.2.0
docker push ghcr.io/yourusername/blutruth:0.2.0
```

---

## Release Automation

### GitHub Actions Workflow

Create `.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install build tools
        run: |
          pip install build twine

      - name: Build distribution
        run: python -m build

      - name: Create GitHub Release
        uses: actions/create-release@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          tag_name: ${{ github.ref }}
          release_name: Release ${{ github.ref }}
          body_path: CHANGELOG.md

      - name: Upload to PyPI
        run: |
          twine upload dist/* -u __token__ -p ${{ secrets.PYPI_TOKEN }}

      - name: Build & push Docker image
        uses: docker/build-push-action@v4
        with:
          push: true
          tags: |
            yourusername/blutruth:${{ github.ref_name }}
            yourusername/blutruth:latest
          registry: docker.io
```

### Manual Release Script

```bash
#!/bin/bash
set -e

VERSION=${1:-}
if [ -z "$VERSION" ]; then
    echo "Usage: ./release.sh 0.2.0"
    exit 1
fi

# Verify version format
if ! [[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Invalid version format. Use X.Y.Z"
    exit 1
fi

# Update version
sed -i "s/version = .*/version = \"$VERSION\"/" pyproject.toml
sed -i "s/__version__ = .*/__version__ = \"$VERSION\"/" blutruth/__init__.py

# Build
python -m build

# Test
pytest

# Tag & push
git add pyproject.toml blutruth/__init__.py
git commit -m "Release v$VERSION"
git tag "v$VERSION"
git push origin main --tags

# Upload to PyPI
twine upload dist/*

echo "✅ Released v$VERSION to PyPI"
```

Run:

```bash
chmod +x release.sh
./release.sh 0.2.0
```

---

## Troubleshooting

### PyPI Upload Fails: "Invalid Distribution"

```
HTTPError: 400 Bad Request
```

**Fix**: Ensure `pyproject.toml` is valid:

```bash
pip install build twine
twine check dist/*  # Will show validation errors
```

### Wheel Won't Install

```
ERROR: Could not find a version that satisfies the requirement blutruth
```

**Fixes**:
1. Check PyPI page: https://pypi.org/project/blutruth/
2. Wait 2-3 minutes for PyPI to index
3. Clear pip cache: `pip cache purge`
4. Reinstall: `pip install --no-cache-dir blutruth`

### Homebrew Formula Not Found

```
Error: No available formula with the name "blutruth"
```

**Fixes**:
1. If using custom tap: `brew tap yourusername/blutruth`
2. If submitting to core: PR must be merged first
3. Check formula is in correct location: `brew edit blutruth`

### Docker Build Fails

```
COPY . . : failed to solve with frontend dockerfile.v0
```

**Fix**: Ensure `.dockerignore` excludes large files:

```
.git
__pycache__
*.pyc
.pytest_cache
build/
dist/
*.egg-info
venv/
```

---

## Release Checklist Template

Use this for each release:

```markdown
## v0.X.Y Release Checklist

- [ ] Bump version in pyproject.toml, __init__.py
- [ ] Update CHANGELOG.md with features/fixes/changes
- [ ] All tests passing: `pytest`
- [ ] Linting clean: `black . && isort .`
- [ ] Type checking: `mypy blutruth/`
- [ ] Build artifacts: `python -m build`
- [ ] Test locally: Install wheel and test CLI
- [ ] Git tag: `git tag vX.Y.Z && git push --tags`
- [ ] Upload to TestPyPI (optional but recommended)
- [ ] Upload to production PyPI
- [ ] Update Homebrew formula
- [ ] Build Docker image and push
- [ ] Create GitHub release
- [ ] Announce on Twitter/Discord/Slack
```

---

## See Also

- **PyPI Help**: https://packaging.python.org/guides/distributing-packages-using-setuptools/
- **Homebrew Docs**: https://docs.brew.sh/Formula-Cookbook
- **Docker Docs**: https://docs.docker.com/build/
- **GitHub Actions**: https://docs.github.com/en/actions

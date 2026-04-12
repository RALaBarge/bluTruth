# bluTruth Release Checklist

Complete checklist for releasing bluTruth to PyPI and Homebrew.

## Pre-Release (24 hours before)

- [ ] Create release branch: `git checkout -b release/v0.2.0`
- [ ] Update `CHANGELOG.md` with all changes
- [ ] Review all recent commits for breaking changes
- [ ] Run full test suite: `pytest -v`
- [ ] Check code coverage: `pytest --cov`
- [ ] Lint code: `black . && isort . && flake8`
- [ ] Type check: `mypy blutruth/` (if configured)
- [ ] Build docs (if applicable)
- [ ] Create GitHub issue for release notes
- [ ] Notify maintainers of upcoming release

## Version Bump

```bash
# 1. Decide version number
# Use semver: MAJOR.MINOR.PATCH
# Example: 0.1.0 → 0.2.0 (feature release) or 0.1.1 (bugfix)

# 2. Update version in pyproject.toml
sed -i 's/version = .*/version = "0.2.0"/' pyproject.toml

# 3. Update __init__.py if it exists
sed -i 's/__version__ = .*/__version__ = "0.2.0"/' blutruth/__init__.py

# 4. Commit and tag
git add pyproject.toml blutruth/__init__.py
git commit -m "chore: bump version to 0.2.0"
git tag -a v0.2.0 -m "Release v0.2.0"
```

Or use the release script:

```bash
./release.sh 0.2.0
```

## Testing

- [ ] `pytest` passes (all tests)
- [ ] `pytest tests/` passes
- [ ] No deprecation warnings
- [ ] CLI works: `blutruth --version`
- [ ] CLI help works: `blutruth --help`
- [ ] Can collect data: `blutruth collect --no-hci` (skip HCI if not available)

## Build

```bash
# Clean
rm -rf build/ dist/ *.egg-info

# Build wheel + source
python -m build

# Verify
ls -lh dist/
# Should see:
#   blutruth-0.2.0-py3-none-any.whl
#   blutruth-0.2.0.tar.gz
```

- [ ] Wheel builds successfully
- [ ] Source tarball builds successfully
- [ ] No build warnings

## Verification

```bash
# Test wheel in isolation
python -m venv /tmp/test_wheel
source /tmp/test_wheel/bin/activate
pip install dist/blutruth-*.whl
blutruth --version
# Should print: 0.2.0
```

- [ ] Wheel installs without errors
- [ ] CLI commands work from installed wheel
- [ ] Help text displays correctly
- [ ] Version reports correctly

## PyPI Upload

### TestPyPI (Optional but Recommended)

```bash
# Setup credentials at ~/.pypirc (see PACKAGING.md)

# Upload to test registry
twine upload --repository testpypi dist/*

# Test installation
pip install --index-url https://test.pypi.org/simple/ blutruth
blutruth --version
```

- [ ] TestPyPI upload succeeds
- [ ] Package installable from TestPyPI
- [ ] No warnings or errors

### Production PyPI

```bash
# Upload to production
twine upload dist/*

# Verify
pip install --upgrade blutruth
blutruth --version
```

- [ ] PyPI upload succeeds
- [ ] Package visible on https://pypi.org/project/blutruth/
- [ ] Package installable from production PyPI
- [ ] Installation completes without warnings

## GitHub Release

```bash
# Push commits and tags
git push origin main --tags

# Create GitHub release
gh release create v0.2.0 dist/* \
  --title "Release v0.2.0" \
  --notes-file CHANGELOG.md
```

Or manually:
1. Go to https://github.com/yourusername/blutruth/releases
2. Click "Draft a new release"
3. Select tag: `v0.2.0`
4. Title: "bluTruth v0.2.0"
5. Description: Copy from CHANGELOG.md
6. Upload artifacts: `dist/blutruth-0.2.0.tar.gz` and `.whl`
7. Publish release

- [ ] GitHub release created
- [ ] Release notes are clear and complete
- [ ] Artifacts uploaded to release

## Homebrew Release

### Setup Homebrew Tap (if not done)

```bash
# Clone or create homebrew tap repo
git clone https://github.com/yourusername/homebrew-blutruth
cd homebrew-blutruth

# Create Formula directory
mkdir -p Formula
```

### Create Formula

```bash
# Get SHA256 of release tarball
curl -sL https://github.com/yourusername/blutruth/archive/v0.2.0.tar.gz | shasum -a 256

# Copy sha256 to formula
cat > Formula/blutruth.rb << 'EOF'
class Blutruth < Formula
  desc "Unified Bluetooth diagnostic platform"
  homepage "https://github.com/yourusername/blutruth"
  url "https://github.com/yourusername/blutruth/archive/v0.2.0.tar.gz"
  sha256 "abc123def456..."  # <- paste SHA256 here
  license "MIT"

  depends_on "python@3.11"
  depends_on "dbus"

  def install
    venv = virtualenv_create(libexec, "python3.11")
    venv.pip_install_and_link buildpath
  end

  test do
    system bin/"blutruth", "--version"
  end
end
EOF
```

### Test Locally

```bash
# Test formula
brew install ./Formula/blutruth.rb --verbose

# Verify
blutruth --version
blutruth --help

# Uninstall
brew uninstall blutruth
```

- [ ] Formula installs successfully
- [ ] CLI works from installed formula
- [ ] No dependency issues
- [ ] Uninstall works cleanly

### Publish

```bash
# Commit formula
git add Formula/blutruth.rb
git commit -m "Add blutruth v0.2.0"
git push

# Users can now install with:
# brew tap yourusername/blutruth
# brew install blutruth
```

- [ ] Formula committed to tap repo
- [ ] Tap repo pushed to GitHub
- [ ] Installation instructions documented

## Docker Release

```bash
# Build image
docker build -t blutruth:0.2.0 .

# Tag for registry
docker tag blutruth:0.2.0 yourusername/blutruth:0.2.0
docker tag blutruth:0.2.0 yourusername/blutruth:latest

# Push to registry (e.g., Docker Hub)
docker push yourusername/blutruth:0.2.0
docker push yourusername/blutruth:latest
```

- [ ] Docker image builds successfully
- [ ] Image tags correctly
- [ ] Image pushes to registry
- [ ] Image is pullable: `docker pull yourusername/blutruth:0.2.0`

## Post-Release

```bash
# Merge release branch back to main
git checkout main
git pull origin main
```

- [ ] Update documentation with new version
- [ ] Update README.md with installation instructions
- [ ] Create release announcement (Twitter, Discord, etc.)
- [ ] Update version in docs/conf.py (if using Sphinx)
- [ ] Close release tracking issue
- [ ] Tag release in project management tool (if used)

## Verification URLs

After release, verify these work:

- [ ] PyPI: https://pypi.org/project/blutruth/
- [ ] PyPI Package Page: https://pypi.org/project/blutruth/0.2.0/
- [ ] GitHub Release: https://github.com/yourusername/blutruth/releases/tag/v0.2.0
- [ ] GitHub Archive: https://github.com/yourusername/blutruth/archive/v0.2.0.tar.gz
- [ ] Docker Hub: https://hub.docker.com/r/yourusername/blutruth

## Installation Verification

Test all installation methods:

```bash
# PyPI
pip install blutruth
blutruth --version

# Homebrew (if released)
brew install yourusername/blutruth/blutruth
blutruth --version

# Docker (if released)
docker run yourusername/blutruth --version

# From source
git clone https://github.com/yourusername/blutruth
cd blutruth
git checkout v0.2.0
pip install -e .
blutruth --version
```

- [ ] PyPI installation works
- [ ] Homebrew installation works (if released)
- [ ] Docker installation works (if released)
- [ ] Source installation works

## Issue Resolution

If something goes wrong:

1. **PyPI Upload Failed**
   - Check `twine check dist/*` output
   - Ensure credentials are correct
   - Verify package name is unique

2. **Homebrew Formula Issues**
   - Test formula locally: `brew install ./Formula/blutruth.rb`
   - Update formula with correct SHA256
   - Check Python dependencies

3. **Docker Build Failed**
   - Check Dockerfile syntax
   - Verify base image is available
   - Check system dependencies are installed

4. **Version Mismatch**
   - Ensure all version strings are updated
   - Rebuild from clean state: `rm -rf dist/ && python -m build`

## Communication

After release, communicate:

- [ ] Announce on Twitter: "🎉 bluTruth v0.2.0 released! New features: ... Install with `pip install blutruth`"
- [ ] Post in Discord/Slack channel (if applicable)
- [ ] Email mailing list (if applicable)
- [ ] Update website/documentation site
- [ ] Create blog post (if significant release)

## Rollback Plan

If critical issues are found after release:

1. **Don't delete PyPI package** (violates packaging guidelines)
2. **Yank from PyPI** if absolutely necessary
3. **Create hotfix release** (0.2.1) with fix
4. **Communicate issue** to users
5. **Test extensively** before next release

---

## Quick Release Template

```bash
# 1. Run release script
./release.sh 0.2.0

# 2. Verify git changes
git log --oneline -3
git show

# 3. Push
git push origin main --tags

# 4. Upload to PyPI
twine upload dist/*

# 5. Verify
pip install --upgrade blutruth
blutruth --version

# 6. Release on GitHub (optional but recommended)
gh release create v0.2.0 dist/* --notes-file CHANGELOG.md
```

**Total time**: ~15 minutes for a simple release

---

See also: [PACKAGING.md](d0cs/PACKAGING.md) for detailed instructions.

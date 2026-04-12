# bluTruth Release Preparation

**DO NOT RELEASE YET — this document outlines every step to execute when ready.**

---

## Version Status

| Location | Current | Next |
|----------|---------|------|
| `pyproject.toml` | `0.1.0` | `0.2.0` |
| `blutruth/__init__.py` | `0.1.0` | `0.2.0` |

Recommended next version: **0.2.0** (minor bump — new features/tools since 0.1.0, not a breaking change)

---

## Credentials and Tokens Needed

### PyPI

1. **PyPI account** — create at https://pypi.org/account/register/ (if not done)
2. **API token** — generate at https://pypi.org/manage/account/token/
   - Scope: "Entire account" for first upload, then scope to project `blutruth`
3. **~/.pypirc config** — add token:

```ini
[pypi]
  username = __token__
  password = pypi-<YOUR_TOKEN_HERE>
```

Or use environment variable at upload time:
```bash
TWINE_USERNAME=__token__ TWINE_PASSWORD=pypi-<YOUR_TOKEN> twine upload dist/*
```

4. **TestPyPI token (optional but recommended)** — generate at https://test.pypi.org/manage/account/token/

```ini
[testpypi]
  username = __token__
  password = pypi-<YOUR_TESTPYPI_TOKEN_HERE>
```

### Homebrew Tap

1. **GitHub repo** named `homebrew-blutruth` under your account
   - Users will install with: `brew tap <username>/blutruth`
   - URL pattern: `https://github.com/<username>/homebrew-blutruth`
2. **GitHub push access** to that repo (your existing credentials work)
3. No special tokens needed — standard `git push` after formula creation

### GitHub Release (optional, recommended)

1. **`gh` CLI installed and authenticated:** `gh auth login`
2. Or create release manually at https://github.com/<username>/blutruth/releases

---

## Step-by-Step Release Process

### Step 1: Pre-flight checks

```bash
cd /home/jinx/ai-stack/bluTruth

# Ensure all tests pass
pytest -v

# Lint (install if needed: pip install black isort flake8)
black . && isort . && flake8 blutruth/

# Verify build tools installed
pip install --upgrade build twine

# Confirm current version
grep version pyproject.toml
```

### Step 2: Run the release script

```bash
./release.sh 0.2.0
```

The script will:
- Validate version format (semver)
- Check for uncommitted changes (fails if dirty)
- Update `pyproject.toml` and `blutruth/__init__.py` to `0.2.0`
- Run the full test suite
- Build wheel + source tarball into `dist/`
- Run `twine check dist/*` to validate packaging
- Commit the version bump and create git tag `v0.2.0`

### Step 3: Push to GitHub

```bash
git push origin main --tags
```

This pushes the version bump commit and the `v0.2.0` tag.

### Step 4: Upload to PyPI

```bash
# TestPyPI first (optional but recommended)
twine upload --repository testpypi dist/*

# Verify TestPyPI install
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ blutruth==0.2.0
blutruth --version  # Should print: 0.2.0

# Production PyPI
twine upload dist/*
```

### Step 5: Create GitHub Release

```bash
gh release create v0.2.0 dist/* \
  --title "bluTruth v0.2.0" \
  --notes "Bluetooth diagnostic platform v0.2.0 — see CHANGELOG.md for details"
```

Or manually at https://github.com/<username>/blutruth/releases/new

---

## Homebrew Tap Setup (homebrew-blutruth)

### One-time setup

```bash
# Create the tap repository on GitHub (one time)
gh repo create homebrew-blutruth --public --description "Homebrew tap for bluTruth"

# Clone it
git clone https://github.com/<username>/homebrew-blutruth ~/homebrew-blutruth
mkdir -p ~/homebrew-blutruth/Formula
```

### Create the formula (run after GitHub release exists)

```bash
# Get SHA256 of the release tarball (do this AFTER GitHub release is published)
SHA=$(curl -sL https://github.com/<username>/blutruth/archive/v0.2.0.tar.gz | shasum -a 256 | awk '{print $1}')
echo "SHA256: $SHA"

cat > ~/homebrew-blutruth/Formula/blutruth.rb << EOF
class Blutruth < Formula
  desc "Bluetooth Stack Diagnostic Platform — unified timeline correlation"
  homepage "https://github.com/<username>/blutruth"
  url "https://github.com/<username>/blutruth/archive/v0.2.0.tar.gz"
  sha256 "$SHA"
  license "MIT"
  head "https://github.com/<username>/blutruth.git", branch: "main"

  depends_on "python@3.11"

  def install
    venv = virtualenv_create(libexec, "python3.11")
    venv.pip_install_and_link buildpath
  end

  test do
    system bin/"blutruth", "--version"
  end
end
EOF

# Test locally before publishing
brew install --build-from-source ~/homebrew-blutruth/Formula/blutruth.rb
blutruth --version
brew uninstall blutruth

# Push the formula
cd ~/homebrew-blutruth
git add Formula/blutruth.rb
git commit -m "Add blutruth v0.2.0"
git push
```

### User installation after tap is published

```bash
brew tap <username>/blutruth
brew install blutruth
```

---

## Verification URLs

After release, verify each:

- PyPI package page: https://pypi.org/project/blutruth/0.2.0/
- PyPI install test: `pip install blutruth==0.2.0`
- GitHub release: https://github.com/<username>/blutruth/releases/tag/v0.2.0
- GitHub archive: https://github.com/<username>/blutruth/archive/v0.2.0.tar.gz
- Homebrew install: `brew tap <username>/blutruth && brew install blutruth`

---

## Installation Verification Tests

Run these after publishing to confirm everything works end-to-end:

```bash
# Test 1: Fresh PyPI install in isolated venv
python -m venv /tmp/blutruth_test
source /tmp/blutruth_test/bin/activate
pip install blutruth==0.2.0
blutruth --version      # expected: 0.2.0
blutruth --help         # expected: usage text
deactivate
rm -rf /tmp/blutruth_test

# Test 2: Upgrade from 0.1.0
pip install blutruth==0.1.0
pip install --upgrade blutruth
blutruth --version      # expected: 0.2.0

# Test 3: Homebrew (macOS only, after tap is published)
brew tap <username>/blutruth
brew install blutruth
blutruth --version
brew uninstall blutruth
```

---

## Quick Reference: Full Release in One Block

```bash
cd /home/jinx/ai-stack/bluTruth

# 1. Release script (bumps version, runs tests, builds, tags)
./release.sh 0.2.0

# 2. Push code + tag
git push origin main --tags

# 3. Upload to PyPI
twine upload dist/*

# 4. GitHub release (optional)
gh release create v0.2.0 dist/* --title "bluTruth v0.2.0"

# 5. Update Homebrew formula (after step 4)
# (follow the Homebrew Tap Setup section above)
```

**Estimated time:** ~15 minutes for PyPI, ~10 additional minutes for Homebrew tap.

---

## Notes

- The `release.sh` script will abort if there are uncommitted changes — commit or stash before running.
- The `yourusername` placeholder appears in several existing files (README, RELEASE_CHECKLIST, formula template) — replace with the actual GitHub username throughout.
- `dbus-next` dependency is Linux-only; macOS Homebrew formula may need this stripped or conditionally skipped.
- Consider adding a `CHANGELOG.md` before 0.2.0 to document changes for users.
- See `RELEASE_CHECKLIST.md` for a printable checkbox version of this process.
- See `d0cs/PACKAGING.md` for deeper packaging background.

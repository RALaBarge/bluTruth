#!/bin/bash
# bluTruth Release Script
# Usage: ./release.sh 0.2.0

set -e

VERSION=${1:-}
if [ -z "$VERSION" ]; then
    echo "❌ Usage: $0 <version>"
    echo "   Example: $0 0.2.0"
    exit 1
fi

# Validate version format (semver)
if ! [[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "❌ Invalid version format '$VERSION'. Must be X.Y.Z (semver)"
    exit 1
fi

echo "🚀 Releasing bluTruth v$VERSION"
echo ""

# Check for uncommitted changes
if [ -n "$(git status --porcelain)" ]; then
    echo "❌ Uncommitted changes detected. Commit or stash first."
    git status
    exit 1
fi

# Check we're on main/master
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$BRANCH" != "main" ] && [ "$BRANCH" != "master" ]; then
    echo "⚠️  Current branch is '$BRANCH', not 'main'. Continue? (y/n)"
    read -r response
    if [ "$response" != "y" ]; then
        exit 1
    fi
fi

echo "✅ Checks passed"
echo ""

# Step 1: Update version
echo "📝 Updating version strings..."
sed -i "s/^version = .*/version = \"$VERSION\"/" pyproject.toml

# Also update in __init__.py if it exists
if [ -f "blutruth/__init__.py" ]; then
    sed -i "s/__version__ = .*/__version__ = \"$VERSION\"/" blutruth/__init__.py
fi
echo "   ✓ pyproject.toml"

# Step 2: Run tests
echo ""
echo "🧪 Running tests..."
if ! pytest -q; then
    echo "❌ Tests failed. Fix and try again."
    git checkout pyproject.toml blutruth/__init__.py 2>/dev/null || true
    exit 1
fi
echo "   ✓ All tests passed"

# Step 3: Build
echo ""
echo "🔨 Building distribution..."
rm -rf build dist *.egg-info
python -m build > /dev/null 2>&1
echo "   ✓ Built wheel and source distribution"

# Step 4: Verify artifacts
echo ""
echo "📦 Verifying artifacts..."
if ! twine check dist/* > /dev/null 2>&1; then
    echo "❌ Twine check failed. See output above."
    exit 1
fi
echo "   ✓ Distributions are valid"

# Step 5: Git operations
echo ""
echo "📌 Creating git tag..."
git add pyproject.toml blutruth/__init__.py 2>/dev/null || git add pyproject.toml
git commit -m "chore: bump version to $VERSION" > /dev/null
git tag -a "v$VERSION" -m "Release v$VERSION" > /dev/null 2>&1 || git tag "v$VERSION"
echo "   ✓ Tagged v$VERSION"

# Step 6: Ready for upload
echo ""
echo "✨ Release ready!"
echo ""
echo "📤 Next steps:"
echo "   1. Review changes: git log --oneline -3"
echo "   2. Push to GitHub: git push origin main --tags"
echo "   3. Upload to PyPI: twine upload dist/*"
echo "   4. Create GitHub Release: gh release create v$VERSION dist/*"
echo ""
echo "Or run all at once:"
echo "   git push origin main --tags && twine upload dist/*"
echo ""

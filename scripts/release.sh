#!/bin/bash

# Usage: ./scripts/release.sh [version]
# If no version is provided, it will read from package.json
# If version is provided, it will override package.json version

# Check if required tools are available
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed"
    echo "   Please install Node.js to read package.json"
    exit 1
fi

# Check if we're in a git repository with origin remote
if ! git rev-parse --git-dir &> /dev/null; then
    echo "❌ Not in a git repository"
    echo "   Make sure you're in a git repository"
    exit 1
fi

if ! git remote get-url origin &> /dev/null; then
    echo "❌ No 'origin' remote found"
    echo "   Make sure you have an 'origin' remote configured"
    exit 1
fi

# Function to get version from package.json
get_package_version() {
    node -p "require('./package.json').version"
}

# Function to check if tag exists remotely
check_tag_exists() {
    local tag=$1
    
    # Check if tag exists on remote
    if git ls-remote --tags origin | grep -q "refs/tags/$tag$"; then
        return 0  # Tag exists
    else
        return 1  # Tag doesn't exist
    fi
}

VERSION=$(get_package_version)

if [ -z "$VERSION" ]; then
   echo "❌ Failed to read version from package.json"
   exit 1
fi

echo "📦 Using version from package.json: $VERSION"

TAG="v$VERSION"

# Check if tag already exists remotely
echo "🔍 Checking if tag $TAG already exists on remote..."
if check_tag_exists "$TAG"; then
    echo "❌ Tag $TAG already exists on remote!"
    exit 1
fi

echo "✅ No existing tag found for $TAG"
echo "🏷️  Creating and pushing tag: $TAG"

# Create and push tag
git tag "$TAG" && git push origin "$TAG"

if [ $? -eq 0 ]; then
    echo "✅ Successfully created and pushed tag: $TAG"
    echo "🚀 GitHub Action should now be running for the release"
else
    echo "❌ Failed to create/push tag"
    exit 1
fi 
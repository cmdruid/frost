#!/bin/bash

# DUCAT Core Package Script
# Runs the complete packaging pipeline: lint → typecheck → test → build

set -e  # Exit on any error

echo "🔧 Starting package process..."

# Step 1: Lint
echo "📝 Running linter..."
npm run lint

# Step 2: Type checking
echo "🔍 Running type check..."
npm run check

# Step 3: Run tests
echo "🧪 Running tests..."
npm run test | npx faucet

# Step 4: Build
echo "🏗️  Building project..."
npm run build

echo "✅ Package process completed successfully!"
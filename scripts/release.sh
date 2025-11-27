#!/usr/bin/env bash
# Release script for Linux System Hardener
# Usage: ./scripts/release.sh [patch|minor|major] [--dry-run]

set -euo pipefail

# Colours for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Colour

# Default values
DRY_RUN=false
BUMP_TYPE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        patch|minor|major)
            BUMP_TYPE="$1"
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [patch|minor|major] [--dry-run]"
            echo ""
            echo "Arguments:"
            echo "  patch     Bump patch version (0.1.0 -> 0.1.1)"
            echo "  minor     Bump minor version (0.1.0 -> 0.2.0)"
            echo "  major     Bump major version (0.1.0 -> 1.0.0)"
            echo ""
            echo "Options:"
            echo "  --dry-run  Show what would be done without making changes"
            echo "  -h, --help Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown argument: $1${NC}"
            exit 1
            ;;
    esac
done

# Validate bump type
if [[ -z "$BUMP_TYPE" ]]; then
    echo -e "${RED}Error: Please specify version bump type (patch, minor, or major)${NC}"
    echo "Usage: $0 [patch|minor|major] [--dry-run]"
    exit 1
fi

# Check we're on main or master branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ "$CURRENT_BRANCH" != "main" && "$CURRENT_BRANCH" != "master" ]]; then
    echo -e "${RED}Error: Releases must be created from main or master branch${NC}"
    echo "Current branch: $CURRENT_BRANCH"
    exit 1
fi

# Check for uncommitted changes
if [[ -n $(git status --porcelain) ]]; then
    echo -e "${RED}Error: Working directory has uncommitted changes${NC}"
    echo "Please commit or stash your changes before releasing."
    exit 1
fi

# Get current version from Cargo.toml
CURRENT_VERSION=$(grep -m1 'version = "' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
echo -e "${BLUE}Current version: ${CURRENT_VERSION}${NC}"

# Calculate new version
IFS='.' read -ra VERSION_PARTS <<< "$CURRENT_VERSION"
MAJOR=${VERSION_PARTS[0]}
MINOR=${VERSION_PARTS[1]}
PATCH=${VERSION_PARTS[2]}

case $BUMP_TYPE in
    major)
        MAJOR=$((MAJOR + 1))
        MINOR=0
        PATCH=0
        ;;
    minor)
        MINOR=$((MINOR + 1))
        PATCH=0
        ;;
    patch)
        PATCH=$((PATCH + 1))
        ;;
esac

NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"
echo -e "${GREEN}New version: ${NEW_VERSION}${NC}"

if $DRY_RUN; then
    echo -e "\n${YELLOW}=== DRY RUN - No changes will be made ===${NC}\n"
fi

# Step 1: Run tests
echo -e "\n${BLUE}Step 1: Running tests...${NC}"
if $DRY_RUN; then
    echo "Would run: cargo test --workspace"
else
    cargo test --workspace
fi

# Step 2: Run clippy
echo -e "\n${BLUE}Step 2: Running clippy...${NC}"
if $DRY_RUN; then
    echo "Would run: cargo clippy --workspace"
else
    cargo clippy --workspace || true  # Don't fail on warnings
fi

# Step 3: Update version in Cargo.toml
echo -e "\n${BLUE}Step 3: Updating version in Cargo.toml...${NC}"
if $DRY_RUN; then
    echo "Would update version from ${CURRENT_VERSION} to ${NEW_VERSION}"
else
    sed -i "s/^version = \"${CURRENT_VERSION}\"/version = \"${NEW_VERSION}\"/" Cargo.toml
fi

# Step 4: Update CHANGELOG.md
echo -e "\n${BLUE}Step 4: Updating CHANGELOG.md...${NC}"
TODAY=$(date +%Y-%m-%d)
if $DRY_RUN; then
    echo "Would update CHANGELOG.md with version ${NEW_VERSION} dated ${TODAY}"
else
    # Replace [Unreleased] with new version section
    sed -i "s/## \[Unreleased\]/## [Unreleased]\n\n## [${NEW_VERSION}] - ${TODAY}/" CHANGELOG.md
fi

# Step 5: Update Cargo.lock
echo -e "\n${BLUE}Step 5: Updating Cargo.lock...${NC}"
if $DRY_RUN; then
    echo "Would run: cargo update --workspace"
else
    cargo update --workspace
fi

# Step 6: Commit version bump
echo -e "\n${BLUE}Step 6: Creating version bump commit...${NC}"
if $DRY_RUN; then
    echo "Would commit with message: chore(release): bump version to ${NEW_VERSION}"
else
    git add Cargo.toml Cargo.lock CHANGELOG.md
    git commit -m "chore(release): bump version to ${NEW_VERSION}"
fi

# Step 7: Create tag
echo -e "\n${BLUE}Step 7: Creating git tag...${NC}"
TAG_NAME="v${NEW_VERSION}"
if $DRY_RUN; then
    echo "Would create tag: ${TAG_NAME}"
else
    git tag -a "${TAG_NAME}" -m "Release ${NEW_VERSION}"
fi

# Step 8: Push to remotes (both branches on both remotes)
echo -e "\n${BLUE}Step 8: Pushing to remotes...${NC}"
if $DRY_RUN; then
    echo "Would push to all remotes and branches:"
    echo "  - origin/master"
    echo "  - origin/main"
    echo "  - origin/${TAG_NAME}"
    echo "  - gitlab/master"
    echo "  - gitlab/main"
    echo "  - gitlab/${TAG_NAME}"
else
    echo "Pushing to origin (GitHub)..."
    git push origin "${CURRENT_BRANCH}" || echo -e "${YELLOW}GitHub ${CURRENT_BRANCH} push failed${NC}"

    # Sync the other branch on GitHub
    if [[ "$CURRENT_BRANCH" == "master" ]]; then
        git push origin master:main || echo -e "${YELLOW}GitHub master:main sync failed${NC}"
    else
        git push origin main:master || echo -e "${YELLOW}GitHub main:master sync failed${NC}"
    fi

    git push origin "${TAG_NAME}" || echo -e "${YELLOW}GitHub tag push failed${NC}"

    echo "Pushing to gitlab..."
    git push gitlab "${CURRENT_BRANCH}" || echo -e "${YELLOW}GitLab ${CURRENT_BRANCH} push failed${NC}"

    # Sync the other branch on GitLab
    if [[ "$CURRENT_BRANCH" == "master" ]]; then
        git push gitlab master:main || echo -e "${YELLOW}GitLab master:main sync failed${NC}"
    else
        git push gitlab main:master || echo -e "${YELLOW}GitLab main:master sync failed${NC}"
    fi

    git push gitlab "${TAG_NAME}" || echo -e "${YELLOW}GitLab tag push failed${NC}"
fi

# Summary
echo -e "\n${GREEN}=== Release Summary ===${NC}"
echo -e "Version: ${CURRENT_VERSION} -> ${NEW_VERSION}"
echo -e "Tag: ${TAG_NAME}"
echo -e "Branch: ${CURRENT_BRANCH}"
echo -e "Synced: master <-> main on both remotes"

if $DRY_RUN; then
    echo -e "\n${YELLOW}This was a dry run. No changes were made.${NC}"
    echo "Run without --dry-run to perform the actual release."
else
    echo -e "\n${GREEN}Release ${NEW_VERSION} complete!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Monitor CI pipelines on GitHub and GitLab"
    echo "2. Verify release assets are published correctly"
    echo "3. Update any external documentation if needed"
fi

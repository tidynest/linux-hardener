#!/usr/bin/env bash
# Release script for Linux System Hardener
# Usage: ./scripts/release/release.sh [patch|minor|major] [--dry-run]
#        ./scripts/release/release.sh --verify

set -euo pipefail

# Resolve the repository root (this script lives in scripts/release/) and run
# from there: every path below (Cargo.toml, docs/, packaging/assets/, git adds) is
# repo-relative.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# Colours for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Colour

# Default values
DRY_RUN=false
BUMP_TYPE=""
VERIFY_ONLY=false

# Function to verify all version references match
verify_versions() {
    echo -e "${BLUE}Verifying version consistency...${NC}"

    # Get version from Cargo.toml workspace.package
    local cargo_version
    cargo_version=$(grep -A1 '^\[workspace\.package\]' Cargo.toml | grep 'version' | sed 's/.*"\(.*\)".*/\1/')

    local all_match=true
    local mismatches=()

    # Check docs/architecture/architecture.md
    if [[ -f "docs/architecture/architecture.md" ]]; then
        local arch_version
        arch_version=$(grep '^\*\*Version:\*\*' docs/architecture/architecture.md | sed 's/.*\*\* \([0-9]\+\.[0-9]\+\.[0-9]\+\).*/\1/' || echo "NOT_FOUND")
        if [[ "$arch_version" != "$cargo_version" ]]; then
            all_match=false
            mismatches+=("docs/architecture/architecture.md: $arch_version")
        fi
    fi

    # Check packaging/assets/hardener.1 (.TH header)
    if [[ -f "packaging/assets/hardener.1" ]]; then
        local man_version
        man_version=$(grep '^\.\s*TH' packaging/assets/hardener.1 | sed 's/.*"\([0-9]\+\.[0-9]\+\.[0-9]\+\)".*/\1/' || echo "NOT_FOUND")
        if [[ "$man_version" != "$cargo_version" ]]; then
            all_match=false
            mismatches+=("packaging/assets/hardener.1: $man_version")
        fi
    fi

    # Check src-tauri/tauri.conf.json
    if [[ -f "src-tauri/tauri.conf.json" ]]; then
        local tauri_version
        tauri_version=$(grep '"version"' src-tauri/tauri.conf.json | head -1 | sed 's/.*"\([0-9]\+\.[0-9]\+\.[0-9]\+\)".*/\1/' || echo "NOT_FOUND")
        if [[ "$tauri_version" != "$cargo_version" ]]; then
            all_match=false
            mismatches+=("src-tauri/tauri.conf.json: $tauri_version")
        fi
    fi

    # Report results
    echo -e "  Cargo.toml (workspace): ${GREEN}${cargo_version}${NC}"

    if $all_match; then
        echo -e "  architecture.md:        ${GREEN}${cargo_version}${NC}"
        echo -e "  packaging/assets/hardener.1:        ${GREEN}${cargo_version}${NC}"
        echo -e "  tauri.conf.json:        ${GREEN}${cargo_version}${NC}"
        echo -e "\n${GREEN}✓ All version references match${NC}"
        return 0
    else
        for mismatch in "${mismatches[@]}"; do
            echo -e "  ${RED}✗ ${mismatch}${NC}"
        done
        echo -e "\n${RED}Version mismatch detected!${NC}"
        echo "Run './scripts/release/release.sh patch|minor|major' to synchronise versions."
        return 1
    fi
}

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
        --verify)
            VERIFY_ONLY=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [patch|minor|major] [--dry-run]"
            echo "       $0 --verify"
            echo ""
            echo "Arguments:"
            echo "  patch     Bump patch version (0.1.0 -> 0.1.1)"
            echo "  minor     Bump minor version (0.1.0 -> 0.2.0)"
            echo "  major     Bump major version (0.1.0 -> 1.0.0)"
            echo ""
            echo "Options:"
            echo "  --verify   Check that all version references match (no changes)"
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

# Handle --verify mode
if $VERIFY_ONLY; then
    verify_versions
    exit $?
fi

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

# Step 1: Run tests (and capture test count for README update)
echo -e "\n${BLUE}Step 1: Running tests...${NC}"
TEST_COUNT=0
if $DRY_RUN; then
    echo "Would run: cargo test --workspace"
    TEST_COUNT="(dry-run)"
else
    TEST_OUTPUT=$(cargo test --workspace 2>&1)
    echo "$TEST_OUTPUT"
    # Extract total test count from "test result:" lines
    TEST_COUNT=$(echo "$TEST_OUTPUT" | grep -E "^test result:" | awk '{sum += $4} END {print sum}')
    echo -e "\n${GREEN}Total tests passed: ${TEST_COUNT}${NC}"
fi

# Step 2: Run clippy
echo -e "\n${BLUE}Step 2: Running clippy...${NC}"
if $DRY_RUN; then
    echo "Would run: cargo clippy --workspace"
else
    cargo clippy --workspace || true  # Don't fail on warnings
fi

# Step 2b: Auto-update documentation
echo -e "\n${BLUE}Step 2b: Auto-updating documentation...${NC}"
VALIDATE_DIR="${REPO_ROOT}/scripts/validate"
if [[ -f "${VALIDATE_DIR}/update_all_docs.py" ]]; then
    if $DRY_RUN; then
        echo "Would run: python3 ${VALIDATE_DIR}/update_all_docs.py --apply"
        python3 "${VALIDATE_DIR}/update_all_docs.py" || true
    else
        python3 "${VALIDATE_DIR}/update_all_docs.py" --apply || true
    fi
else
    echo -e "${YELLOW}Warning: update_all_docs.py not found, skipping auto-update${NC}"
fi

# Step 2c: Validate documentation
echo -e "\n${BLUE}Step 2c: Validating documentation...${NC}"
if [[ -f "${VALIDATE_DIR}/validate_all.py" ]]; then
    if ! python3 "${VALIDATE_DIR}/validate_all.py" --quick; then
        echo -e "\n${YELLOW}Warning: Some documentation validations failed.${NC}"
        echo "These may require manual fixes before release."
        read -p "Continue with release anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${RED}Release aborted.${NC}"
            exit 1
        fi
    fi
else
    echo -e "${YELLOW}Warning: validate_all.py not found, skipping validation${NC}"
fi

# Step 3: Update version in Cargo.toml (workspace.package.version)
echo -e "\n${BLUE}Step 3: Updating version in Cargo.toml...${NC}"
if $DRY_RUN; then
    echo "Would update workspace version from ${CURRENT_VERSION} to ${NEW_VERSION}"
else
    # Update the workspace.package version (not a top-level version)
    sed -i "s/^\[workspace\.package\]$/[workspace.package]\nVERSION_MARKER/" Cargo.toml
    sed -i "/VERSION_MARKER/{n;s/version = \"${CURRENT_VERSION}\"/version = \"${NEW_VERSION}\"/}" Cargo.toml
    sed -i "/VERSION_MARKER/d" Cargo.toml
fi

# Step 3b: Update version in documentation files
echo -e "\n${BLUE}Step 3b: Updating version in documentation...${NC}"
DOC_FILES=(
    "docs/architecture/architecture.md"
)
for doc_file in "${DOC_FILES[@]}"; do
    if [[ -f "$doc_file" ]]; then
        if $DRY_RUN; then
            echo "Would update version in $doc_file"
        else
            # Update "**Version:** X.Y.Z" pattern
            sed -i "s/^\*\*Version:\*\* [0-9]\+\.[0-9]\+\.[0-9]\+/**Version:** ${NEW_VERSION}/" "$doc_file"
            echo "  Updated $doc_file"
        fi
    fi
done

# Update man page version in .TH header
if [[ -f "packaging/assets/hardener.1" ]]; then
    if $DRY_RUN; then
        echo "Would update version in packaging/assets/hardener.1"
    else
        sed -i "s/^\(\.TH HARDENER 1 \"[^\"]*\" \"\)[0-9]\+\.[0-9]\+\.[0-9]\+/\1${NEW_VERSION}/" "packaging/assets/hardener.1"
        echo "  Updated packaging/assets/hardener.1"
    fi
fi

# Update Tauri desktop app version
if [[ -f "src-tauri/tauri.conf.json" ]]; then
    if $DRY_RUN; then
        echo "Would update version in src-tauri/tauri.conf.json"
    else
        sed -i "s/\"version\": \"[0-9]\+\.[0-9]\+\.[0-9]\+\"/\"version\": \"${NEW_VERSION}\"/" "src-tauri/tauri.conf.json"
        echo "  Updated src-tauri/tauri.conf.json"
    fi
fi

# Step 3c: Update test count in README.md
echo -e "\n${BLUE}Step 3c: Updating test count in README.md...${NC}"
if $DRY_RUN; then
    echo "Would update test count to ${TEST_COUNT}+ in README.md"
else
    if [[ "$TEST_COUNT" =~ ^[0-9]+$ ]]; then
        # Update "Total Tests: XXX+ passing" line
        sed -i "s/^Total Tests: [0-9]\+/Total Tests: ${TEST_COUNT}/" README.md
        echo "  Updated test count to ${TEST_COUNT}+"
    else
        echo -e "  ${YELLOW}Skipped: Could not determine test count${NC}"
    fi
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
    # Add all potentially modified documentation files
    git add Cargo.toml Cargo.lock CHANGELOG.md README.md SECURITY.md CONTRIBUTING.md
    git add docs/ 2>/dev/null || true
    git add scripts/README.md 2>/dev/null || true
    git add packaging/assets/hardener.1 2>/dev/null || true
    git add src-tauri/tauri.conf.json 2>/dev/null || true
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

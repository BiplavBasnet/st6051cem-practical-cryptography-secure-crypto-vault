#!/bin/bash
# Bash script to remove git files from GitHub
# Run this script from the project directory

echo "=== GitHub Cleanup Script ==="
echo ""

# Check if we're in a git repository
if [ ! -d .git ]; then
    echo "ERROR: Not in a git repository!"
    echo "Please run this script from the project root directory."
    exit 1
fi

echo "⚠️  SECURITY WARNING:"
echo "Make sure you have revoked any exposed GitHub tokens first!"
echo "Visit: https://github.com/settings/tokens"
echo ""
read -p "Have you revoked the token? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Please revoke the token first at: https://github.com/settings/tokens"
    exit 1
fi

echo ""
echo "Removing files from git tracking..."

# List of files to remove
files=(
    "git_automator.py"
    "install_git_automation.bat"
    "generate_changelog.py"
    "generate_changelog_with_diffs.py"
    "update_commits.py"
    "commit_history.txt"
    "CHANGELOG.md"
    "CHANGELOG_HARDENING.md"
    "COMPLETE_CHANGELOG.md"
)

# Remove files from git tracking
for file in "${files[@]}"; do
    if git ls-files --error-unmatch "$file" &>/dev/null; then
        echo "  Removing: $file"
        git rm "$file" 2>/dev/null
    else
        echo "  Skipping: $file (not tracked)"
    fi
done

# Stage README.md changes
if git diff --name-only HEAD | grep -q "README.md"; then
    echo "  Staging: README.md"
    git add README.md
fi

# Check if there are changes to commit
if [ -n "$(git status --porcelain)" ]; then
    echo ""
    echo "Changes to be committed:"
    git status --short
    
    echo ""
    read -p "Commit these changes? (yes/no): " commit
    if [ "$commit" = "yes" ]; then
        git commit -m "chore: remove git automation scripts and changelog files"
        echo "✓ Changes committed"
        
        echo ""
        read -p "Push to GitHub? (yes/no): " push
        if [ "$push" = "yes" ]; then
            branch=$(git branch --show-current)
            echo "Pushing to origin/$branch..."
            git push origin "$branch"
            echo "✓ Pushed to GitHub"
        else
            echo "Changes committed locally. Push manually with: git push origin <branch>"
        fi
    else
        echo "Changes staged but not committed. Commit manually when ready."
    fi
else
    echo ""
    echo "No changes to commit. Files may already be removed."
fi

echo ""
echo "=== Cleanup Complete ==="


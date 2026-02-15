# PowerShell script to remove git files from GitHub
# Run this script from the project directory

Write-Host "=== GitHub Cleanup Script ===" -ForegroundColor Cyan
Write-Host ""

# Check if we're in a git repository
if (-not (Test-Path .git)) {
    Write-Host "ERROR: Not in a git repository!" -ForegroundColor Red
    Write-Host "Please run this script from the project root directory." -ForegroundColor Yellow
    exit 1
}

Write-Host "⚠️  SECURITY WARNING:" -ForegroundColor Red
Write-Host "Make sure you have revoked any exposed GitHub tokens first!" -ForegroundColor Yellow
Write-Host "Visit: https://github.com/settings/tokens" -ForegroundColor Yellow
Write-Host ""
$confirm = Read-Host "Have you revoked the token? (yes/no)"
if ($confirm -ne "yes") {
    Write-Host "Please revoke the token first at: https://github.com/settings/tokens" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Removing files from git tracking..." -ForegroundColor Green

# List of files to remove
$filesToRemove = @(
    "git_automator.py",
    "install_git_automation.bat",
    "generate_changelog.py",
    "generate_changelog_with_diffs.py",
    "update_commits.py",
    "commit_history.txt",
    "CHANGELOG.md",
    "CHANGELOG_HARDENING.md",
    "COMPLETE_CHANGELOG.md"
)

# Remove files from git tracking
foreach ($file in $filesToRemove) {
    if (git ls-files --error-unmatch $file 2>$null) {
        Write-Host "  Removing: $file" -ForegroundColor Yellow
        git rm $file 2>$null
    } else {
        Write-Host "  Skipping: $file (not tracked)" -ForegroundColor Gray
    }
}

# Stage README.md changes
if (git diff --name-only HEAD | Select-String -Pattern "README.md") {
    Write-Host "  Staging: README.md" -ForegroundColor Yellow
    git add README.md
}

# Check if there are changes to commit
$status = git status --porcelain
if ($status) {
    Write-Host ""
    Write-Host "Changes to be committed:" -ForegroundColor Cyan
    git status --short
    
    Write-Host ""
    $commit = Read-Host "Commit these changes? (yes/no)"
    if ($commit -eq "yes") {
        git commit -m "chore: remove git automation scripts and changelog files"
        Write-Host "✓ Changes committed" -ForegroundColor Green
        
        Write-Host ""
        $push = Read-Host "Push to GitHub? (yes/no)"
        if ($push -eq "yes") {
            # Detect branch name
            $branch = git branch --show-current
            Write-Host "Pushing to origin/$branch..." -ForegroundColor Yellow
            git push origin $branch
            Write-Host "✓ Pushed to GitHub" -ForegroundColor Green
        } else {
            Write-Host "Changes committed locally. Push manually with: git push origin <branch>" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Changes staged but not committed. Commit manually when ready." -ForegroundColor Yellow
    }
} else {
    Write-Host ""
    Write-Host "No changes to commit. Files may already be removed." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Cleanup Complete ===" -ForegroundColor Green


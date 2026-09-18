<#
Push this tool to GitHub (Windows / PowerShell). Idempotent - safe to re-run.

Prereqs (already installed if this was set up for you):
  winget install Git.Git GitHub.cli

Usage, from inside this 'tool' folder:
  .\push_to_github.ps1 -Repo vuln-corrector -Visibility private

The script will:
  1. run 'gh auth login' if you are not already logged in (browser),
  2. set a repo-local git identity from your GitHub account (GitHub no-reply
     email, so your real address is never published),
  3. commit and create/push the repo on YOUR account.
#>
param(
    [Parameter(Mandatory = $true)][string]$Repo,
    [ValidateSet('private', 'public')][string]$Visibility = 'private'
)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Need($name, $hint) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) { throw "$name not found. $hint" }
}
Need git "Install: winget install Git.Git (then open a NEW terminal)."
Need gh  "Install: winget install GitHub.cli (then open a NEW terminal)."

# 1. Authenticate if needed
gh auth status 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Not logged in - launching 'gh auth login' (choose GitHub.com -> HTTPS -> browser)..." -ForegroundColor Yellow
    gh auth login
}
$login = (gh api user --jq .login).Trim()
$uid   = (gh api user --jq .id).Trim()
$name  = (gh api user --jq '.name // .login').Trim()
if (-not $login) { throw "Could not read your GitHub login (is 'gh auth login' complete?)." }
$noreply = "$uid+$login@users.noreply.github.com"

# 2. Repo + identity (repo-local, does not touch your global git config)
if (-not (Test-Path .git)) { git init -b main }
if (-not (git config user.email)) {
    git config user.name  "$name"
    git config user.email "$noreply"
    Write-Host "Set repo-local identity: $name <$noreply>" -ForegroundColor Cyan
}

# 3. Commit (only if there is something to commit)
git add .
git commit -m "vuln_corrector: cross-platform Tenable CVSS & rating corrector" 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "Nothing new to commit - continuing." -ForegroundColor DarkGray }

# 4. Create the remote (first run) or just push (subsequent runs)
$hasOrigin = (git remote 2>$null) -contains 'origin'
if (-not $hasOrigin) {
    gh repo create $Repo --$Visibility --source=. --remote=origin --push
} else {
    git push -u origin main
}
Write-Host "`nDone. Repo: https://github.com/$login/$Repo" -ForegroundColor Green

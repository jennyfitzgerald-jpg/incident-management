# Run this AFTER you have run: gh auth login (and completed the browser login).
# This creates the GitHub repo and pushes your code.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

$repoName = "incident-management"
Write-Host "Creating GitHub repo '$repoName' and pushing..." -ForegroundColor Cyan
gh repo create $repoName --public --source=. --remote=origin --push --description "Incident Management with OAuth"
if ($?) { Write-Host "Done. Repo: https://github.com/$((gh api user -q .login))/incident-management" -ForegroundColor Green }
else    { Write-Host "If repo already exists: git push -u origin main" -ForegroundColor Yellow; git push -u origin main }

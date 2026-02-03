# Open the three pages you need to deploy (GitHub, Google OAuth, Streamlit Cloud).
# Run: .\open_deploy_pages.ps1

$urls = @(
    "https://github.com/new?name=incident-management&description=Incident+Management+with+OAuth",
    "https://console.cloud.google.com/apis/credentials",
    "https://share.streamlit.io"
)

foreach ($url in $urls) {
    Start-Process $url
    Start-Sleep -Milliseconds 800
}

Write-Host ""
Write-Host "Opened: (1) GitHub new repo, (2) Google Cloud credentials, (3) Streamlit Cloud" -ForegroundColor Green
Write-Host ""
Write-Host "Next: Create the GitHub repo, then run this in your project folder (replace YOUR_USERNAME and YOUR_REPO):" -ForegroundColor Yellow
Write-Host '  git remote set-url origin https://github.com/YOUR_USERNAME/YOUR_REPO.git'
Write-Host '  git push -u origin main'
Write-Host ""
Write-Host "Then add your app URL and OAuth credentials in Streamlit Cloud Secrets. See DEPLOY_NOW.md" -ForegroundColor Cyan

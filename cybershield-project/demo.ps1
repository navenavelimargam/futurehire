Write-Host "--- DeProxy Live Attack Simulation ---" -ForegroundColor Cyan

# Scenario 1: Normal Traffic
Write-Host "1. Simulating Normal User Traffic..." -ForegroundColor Green
1..5 | ForEach-Object { Invoke-RestMethod -Uri "http://localhost:9090/" -Method Get; Write-Host "." -NoNewline; Start-Sleep -Milliseconds 200 }

# Scenario 2: SQL Injection Attack
Read-Host "`nPress Enter to launch SQL Injection Attack"
Invoke-RestMethod -Method Post -Uri "http://localhost:9090/" -Body "user=' OR 1=1" 

# Scenario 3: XSS Attack
Read-Host "Press Enter to launch XSS Attack"
Invoke-RestMethod -Method Post -Uri "http://localhost:9090/" -Body "<script>alert('XSS')</script>"

# Scenario 4: Rate Limit / DDOS
Read-Host "Press Enter to launch Rate Limit Exhaustion"
1..20 | ForEach-Object { 
    try { (Invoke-WebRequest -Uri "http://localhost:9090/login" -Method Head -UseBasicParsing).StatusCode } catch { "Blocked" }
}
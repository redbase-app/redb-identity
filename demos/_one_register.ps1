$user = "tim_" + [Guid]::NewGuid().ToString("N").Substring(0,8)
$body = @{ login=$user; email="$user@example.com"; password="Test1234Pass!"; displayName=$user } | ConvertTo-Json
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$r = Invoke-RestMethod -Method Post "http://127.0.0.1:5002/api/v1/identity/account/register" -ContentType "application/json" -Body $body
$sw.Stop()
Write-Host ("register: {0:N0} ms login={1} userId={2}" -f $sw.Elapsed.TotalMilliseconds, $r.login, $r.userId)

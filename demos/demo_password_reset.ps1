# Anonymous password-recovery flow (RFC-aligned: N-4 Session C).
#   POST /api/v1/identity/password/forgot — initiate (anti-enumeration: ALWAYS 200,
#     even on unknown email or non-whitelisted callerResetUrl).
#   POST /api/v1/identity/password/reset  — consume the single-use token + set new pwd
#     (rejects with success=false on bad/expired/consumed token, policy violation).
#
# Probes:
#   1.  DCR with password_reset_uris      — client must carry the whitelist
#   2.  self-register user
#   3.  forgot for UNKNOWN email          → 200 (anti-enum)         — NO mail sent
#   4.  forgot with NON-whitelisted url   → 200 (anti-enum)         — NO mail sent
#   5.  forgot HAPPY PATH                 → 200, mail lands in GreenMail with reset link
#   5b. fetch + parse the reset link      — extract jti+token from MIME quoted-printable
#   6.  /reset with BOGUS token           → success=false, generic invalid_token; token NOT consumed
#   7.  /reset HAPPY PATH                 → success=true, sessionsRevoked >= 0
#   8.  login with NEW password           → 200 (token issued)
#   9.  /reset replay (same jti+token)    → success=false (single-use enforced)
#  10.  RFC 7592 DELETE registration cleanup
#
# (Weak-newPassword rejection of /reset is intentionally NOT probed here because the
#  processor consumes the token on Verify, not on Set, so probing weak after a valid
#  token would steal the only token for the happy path. The IPasswordPolicyValidator
#  pipeline is covered exhaustively by demo_password_change_negatives — same validator.)
#
# Requires the GreenMail container (route-greenmail, SMTP 3025 / REST 8080) to be
# running — SMTP is wired in context.json. Without it the happy path can't intercept
# the token and the demo aborts at step 5.
#
# Usage: pwsh -File demo_password_reset.ps1
#requires -Version 7

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
$GM        = "http://127.0.0.1:8080"   # GreenMail REST API
$RESET_URL = "http://localhost:9999/reset-page"
$timings   = [System.Collections.Generic.List[object]]::new()

function Measure-Step {
    param([string]$Name, [scriptblock]$Action)
    Write-Host ""
    Write-Host "=== [$Name] ===" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = & $Action
        $sw.Stop()
        Write-Host ("--- [$Name] {0:N0} ms" -f $sw.Elapsed.TotalMilliseconds) -ForegroundColor Green
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=[math]::Round($sw.Elapsed.TotalMilliseconds,0); Status="ok" })
        return $result
    } catch {
        $sw.Stop()
        Write-Host ("!!! [$Name] FAILED in {0:N0} ms: {1}" -f $sw.Elapsed.TotalMilliseconds, $_.Exception.Message) -ForegroundColor Red
        $timings.Add([pscustomobject]@{ Step=$Name; Ms=[math]::Round($sw.Elapsed.TotalMilliseconds,0); Status="fail" })
        throw
    }
}

# Wait up to $timeoutMs for an email to {email} to land in GreenMail. Returns the
# message object (with subject, body) or $null on timeout.
function Wait-Email {
    param([string]$Email, [int]$TimeoutMs = 8000)
    $deadline = [DateTimeOffset]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        try {
            $msgs = Invoke-RestMethod -Method Get "$GM/api/user/$Email/messages/INBOX" -ErrorAction Stop
            if ($msgs -and $msgs.Count -ge 1) { return $msgs[0] }
        } catch {
            # 404 until the user is auto-created by GreenMail on first mail — retry.
        }
        Start-Sleep -Milliseconds 300
    }
    return $null
}

# Decode quoted-printable encoding used in multipart/alternative MIME bodies:
#   =\r\n       → soft line-break, drop
#   =XX         → byte with hex value XX
function Decode-QuotedPrintable {
    param([string]$s)
    if ([string]::IsNullOrEmpty($s)) { return $s }
    $s = $s -replace "=\r\n", "" -replace "=\n", ""
    return [regex]::Replace($s, "=([0-9A-Fa-f]{2})", {
        param($m) [char][Convert]::ToInt32($m.Groups[1].Value, 16)
    })
}

# Extract (jti, token) from the email body. The reset URL is composed by the server as
#   {CallerResetUrl}?token={plaintext}&jti={jti}
function Extract-ResetTuple {
    param([string]$Body)
    $decoded = Decode-QuotedPrintable -s $Body
    $jtiMatch = [regex]::Match($decoded, 'jti=([^&\s"<>]+)')
    $tokMatch = [regex]::Match($decoded, 'token=([^&\s"<>]+)')
    if (-not $jtiMatch.Success -or -not $tokMatch.Success) {
        throw "could not extract jti / token from decoded mail. Snippet: $($decoded.Substring(0, [Math]::Min(400, $decoded.Length)))"
    }
    return [pscustomobject]@{
        Jti   = [System.Web.HttpUtility]::UrlDecode($jtiMatch.Groups[1].Value)
        Token = [System.Web.HttpUtility]::UrlDecode($tokMatch.Groups[1].Value)
    }
}

Add-Type -AssemblyName System.Web

# Wrapper that POSTs JSON and returns the parsed response BODY whether the server
# replies 200 (success path) or 4xx (rejection with structured error JSON). The
# /password/reset processor returns HTTP 400 on bad/expired/consumed token AND on
# policy violations, with the rejection body itself carrying success=false +
# error/errorDescription — we want the body in both cases.
function Invoke-RestMethodOrError {
    param([string]$Uri, [hashtable]$Body)
    try {
        return Invoke-RestMethod -Method Post $Uri -ContentType "application/json" -Body ($Body | ConvertTo-Json) -ErrorAction Stop
    } catch {
        $resp = $_.ErrorDetails
        if ($resp -and $resp.Message) {
            try { return $resp.Message | ConvertFrom-Json } catch { return [pscustomobject]@{ success = $false; error = "unparseable"; errorDescription = $resp.Message } }
        }
        throw
    }
}

$total = [System.Diagnostics.Stopwatch]::StartNew()

$oldPwd = "Test1234Pass!"
$newPwd = "BrandNewSecret77"

# Purge GreenMail so previous demo runs don't pollute the inbox.
Measure-Step "0. purge GreenMail inbox" {
    Invoke-RestMethod -Method Post "$GM/api/mail/purge" | Out-Null
    Write-Host "  ✓ inbox cleared" -ForegroundColor Green
} | Out-Null

# 1) DCR — register a password client and pin the reset-URL whitelist.
$reg = Measure-Step "1. DCR (password client + password_reset_uris)" {
    $r = Invoke-RestMethod -Method Post "$BASE/connect/register" `
        -ContentType "application/json" `
        -Body (@{
            client_name         = "password-reset-demo"
            grant_types         = @("password","refresh_token")
            scope               = "openid profile email offline_access identity:account"
            password_reset_uris = @($RESET_URL)
        } | ConvertTo-Json -Depth 5)
    if (-not $r.client_id) { throw "DCR did not return client_id" }
    if (-not $r.password_reset_uris) {
        throw "server did not echo password_reset_uris — RFC 7591 metadata extension not active"
    }
    if ($r.password_reset_uris -notcontains $RESET_URL) {
        throw "password_reset_uris mismatch (got: $($r.password_reset_uris -join ','))"
    }
    Write-Host "  ✓ client_id: $($r.client_id)" -ForegroundColor Green
    Write-Host "  ✓ password_reset_uris echoed: $($r.password_reset_uris -join ', ')" -ForegroundColor Green
    return $r
}
$RAT = $reg.registration_access_token
$RCU = $reg.registration_client_uri

# 2) Self-register a fresh user.
$user  = "reset_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$email = "$user@example.com"
Measure-Step "2. self-register ($user)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/account/register" `
        -ContentType "application/json" `
        -Body (@{
            login       = $user
            email       = $email
            password    = $oldPwd
            displayName = $user
        } | ConvertTo-Json) | Out-Null
    Write-Host "  ✓ user created: $email" -ForegroundColor Green
} | Out-Null

# 3) /password/forgot for UNKNOWN email — must still 200 (anti-enumeration).
Measure-Step "3. forgot UNKNOWN email (expect 200, no mail)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/password/forgot" `
        -ContentType "application/json" `
        -Body (@{
            email          = "ghost_$([Guid]::NewGuid().ToString('N').Substring(0,6))@example.com"
            clientId       = $reg.client_id
            callerResetUrl = $RESET_URL
        } | ConvertTo-Json) | Out-Null
    Write-Host "  ✓ 200 returned (anti-enumeration contract honoured)" -ForegroundColor Green
} | Out-Null

# 4) /password/forgot with non-whitelisted callerResetUrl — must still 200, but
#    NO mail must be delivered. We assert mailbox stays empty for 1 second after.
Measure-Step "4. forgot NON-whitelisted callerResetUrl (expect 200, no mail)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/password/forgot" `
        -ContentType "application/json" `
        -Body (@{
            email          = $email
            clientId       = $reg.client_id
            callerResetUrl = "https://attacker.example/steal"
        } | ConvertTo-Json) | Out-Null
    Start-Sleep -Milliseconds 800
    $msg = Wait-Email -Email $email -TimeoutMs 200
    if ($msg) {
        throw "non-whitelisted callerResetUrl SHOULD have been silently dropped, but mail was delivered (subject='$($msg.subject)')"
    }
    Write-Host "  ✓ 200 + no mail leaked" -ForegroundColor Green
} | Out-Null

# 5) /password/forgot HAPPY PATH — real email + whitelisted callerResetUrl.
Measure-Step "5. forgot HAPPY (mail expected in GreenMail)" {
    Invoke-RestMethod -Method Post "$BASE/api/v1/identity/password/forgot" `
        -ContentType "application/json" `
        -Body (@{
            email          = $email
            clientId       = $reg.client_id
            callerResetUrl = $RESET_URL
        } | ConvertTo-Json) | Out-Null
    Write-Host "  ✓ /password/forgot 200 — waiting for mail" -ForegroundColor Green
} | Out-Null

$resetTuple = Measure-Step "5b. fetch reset mail from GreenMail" {
    $msg = Wait-Email -Email $email -TimeoutMs 8000
    if (-not $msg) { throw "mail did not land in GreenMail within 8s" }
    Write-Host "  ✓ mail: subject='$($msg.subject)'" -ForegroundColor Green
    # GreenMail's REST exposes the raw MIME under 'mimeMessage'. The reset URL lives in
    # both multipart/alternative parts; we parse the whole message and let the regex find
    # the first match — works regardless of which part the server emits.
    $raw = $msg.mimeMessage
    if ([string]::IsNullOrWhiteSpace($raw)) { throw "mimeMessage empty (msg keys: $($msg.PSObject.Properties.Name -join ','))" }
    $tup = Extract-ResetTuple -Body $raw
    Write-Host "  ✓ jti = $($tup.Jti)" -ForegroundColor Green
    Write-Host "  ✓ token length = $($tup.Token.Length)" -ForegroundColor Green
    return $tup
}

# 6) /password/reset with BOGUS token (correct jti, wrong token) — token verification
#    must fail with a generic error and MUST NOT consume the jti slot (hash mismatch
#    is detected before consumption in IPasswordResetTokenStore.VerifyAndConsumeAsync).
Measure-Step "6. /reset with BOGUS token (expect success=false, token preserved)" {
    $r = Invoke-RestMethodOrError -Uri "$BASE/api/v1/identity/password/reset" -Body @{
        jti         = $resetTuple.Jti
        token       = "AAAA" + ($resetTuple.Token.Substring(4))
        newPassword = $newPwd
    }
    if ($r.success -eq $true) {
        throw "BOGUS token was accepted — single-use guard / hash compare broken"
    }
    if (-not $r.error) {
        throw "rejection MUST carry an Error field (got: $($r | ConvertTo-Json))"
    }
    Write-Host "  ✓ success=false, error=$($r.error)" -ForegroundColor Green
} | Out-Null

# 7) /password/reset HAPPY PATH with the still-valid jti+token.
#    (Weak-newPassword rejection is covered by demo_password_change_negatives — the
#     same IPasswordPolicyValidator backs both flows. Probing it here would consume
#     the only token we have, since the processor consumes on Verify, not on Set.)
Measure-Step "7. /reset HAPPY (expect success=true)" {
    $r = Invoke-RestMethodOrError -Uri "$BASE/api/v1/identity/password/reset" -Body @{
        jti         = $resetTuple.Jti
        token       = $resetTuple.Token
        newPassword = $newPwd
    }
    if ($r.success -ne $true) {
        throw "happy reset failed (error=$($r.error) desc=$($r.errorDescription))"
    }
    Write-Host "  ✓ success=true, sessionsRevoked=$($r.sessionsRevoked)" -ForegroundColor Green
} | Out-Null

# 8) Login with NEW password works.
Measure-Step "8. login with NEW password (expect token)" {
    $t = Invoke-RestMethod -Method Post "$BASE/connect/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "password"
            client_id     = $reg.client_id
            client_secret = $reg.client_secret
            username      = $user
            password      = $newPwd
            scope         = "openid"
        }
    if (-not $t.access_token) { throw "no access_token after reset" }
    Write-Host "  ✓ new password works (access_token len=$($t.access_token.Length))" -ForegroundColor Green
} | Out-Null

# 9) /password/reset REPLAY — same jti+token must be rejected as already-consumed.
Measure-Step "9. /reset REPLAY (expect success=false, single-use)" {
    $r = Invoke-RestMethodOrError -Uri "$BASE/api/v1/identity/password/reset" -Body @{
        jti         = $resetTuple.Jti
        token       = $resetTuple.Token
        newPassword = "AnotherStrongOne9!"
    }
    if ($r.success -eq $true) {
        throw "token replay accepted — IPasswordResetTokenStore did not consume on first use"
    }
    Write-Host "  ✓ replay rejected: error=$($r.error)" -ForegroundColor Green
} | Out-Null

# 10) RFC 7592 cleanup.
Measure-Step "10. RFC 7592 DELETE registration" {
    if (-not $RAT) { Write-Host "  (no RAT → skip)" -ForegroundColor DarkGray; return }
    Invoke-RestMethod -Method Delete -Uri $RCU -Headers @{ Authorization = "Bearer $RAT" } | Out-Null
    Write-Host "  ✓ client deleted" -ForegroundColor Green
} | Out-Null

$total.Stop()
Write-Host ""
Write-Host "================ TIMING SUMMARY ================" -ForegroundColor Cyan
$timings | Format-Table -AutoSize Step, Ms, Status
Write-Host ("TOTAL: {0:N0} ms" -f $total.Elapsed.TotalMilliseconds) -ForegroundColor Cyan

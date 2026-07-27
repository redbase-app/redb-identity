#requires -Version 7
<#
.SYNOPSIS
    Seeds the End-User the OIDF conformance suite logs in as: `conform` / `Conform1234Pass!`,
    with a FULL OIDC §5.1 profile (every profile/email/phone/address claim populated).

.DESCRIPTION
    The Basic OP scope tests (oidcc-scope-profile / -email / -address / -phone / -all) VERIFY that
    userinfo returns every standard claim implied by the requested scope. A user created with only
    login+email makes those tests WARN ("userinfo doesn't contain all scope items"), which looks
    like a server defect but is just missing data. This script fills the profile so they PASS.

    The conformance worker runs on a dev SQLite DB that is reset on a clean restart, so this user
    is NOT persistent — re-run this after any worker restart during a conformance session.

    Idempotent: re-registering an existing login returns success; the PUT /me overwrites the profile.

.PARAMETER BaseUrl   OP base. Default https://127.0.0.1:5002 (local conformance context).
#>
param([string]$BaseUrl = 'https://127.0.0.1:5002')

$ErrorActionPreference = 'Stop'
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true

# One password-grant client, reused to mint tokens for each seeded user.
$reg = Invoke-RestMethod -Method Post "$BaseUrl/connect/register" -ContentType 'application/json' -Body (@{
    client_name = 'seed-conform'; grant_types = @('password')
    scope = 'openid profile email phone address identity:account'
} | ConvertTo-Json)

function Token($login, $pass, $scope) {
    (Invoke-RestMethod -Method Post "$BaseUrl/connect/token" -ContentType 'application/x-www-form-urlencoded' -Body @{
        grant_type = 'password'; username = $login; password = $pass
        client_id = $reg.client_id; client_secret = $reg.client_secret; scope = $scope
    }).access_token
}

# Fills a user's full OIDC §5.1 profile via PUT /me, then confirms userinfo carries the set.
# The suite's scope tests (oidcc-scope-*) log in as whatever End-User you type on the OP form and
# verify userinfo returns every claim the scope implies — so EVERY user you might log in as needs
# a complete profile, not just one.
function Seed-Profile($login, $pass, $display, $given, $family, $email, $phone) {
    Write-Host "[$login] register + full profile ..." -ForegroundColor Cyan
    try {
        Invoke-RestMethod -Method Post "$BaseUrl/api/v1/identity/account/register" -ContentType 'application/json' -Body (@{
            login = $login; email = $email; password = $pass; displayName = $display
        } | ConvertTo-Json) | Out-Null
    } catch { }   # already exists (e.g. bootstrap admin) — fine, we only need the profile filled

    $tok = Token $login $pass 'openid profile email phone address identity:account'
    Invoke-RestMethod -Method Put "$BaseUrl/api/v1/identity/me" -Headers @{ Authorization = "Bearer $tok" } `
        -ContentType 'application/json' -Body (@{
            email = $email; displayName = $display; givenName = $given; familyName = $family; middleName = 'Test'
            nickname = $login; preferredUsername = $login; profile = "https://example.com/$login"
            picture = "https://example.com/$login.png"; website = 'https://example.com'; gender = 'other'
            birthdate = '1990-01-01'; zoneInfo = 'Europe/Moscow'; locale = 'en-US'; phoneNumber = $phone
            address = @{
                formatted = "1 Test St, Testville, TS 12345, US"; streetAddress = '1 Test St'
                locality = 'Testville'; region = 'TS'; postalCode = '12345'; country = 'US'
            }
        } | ConvertTo-Json -Depth 6) | Out-Null

    $ui = Invoke-RestMethod "$BaseUrl/connect/userinfo" -Headers @{ Authorization = (Token $login $pass 'openid profile email phone address' | ForEach-Object { "Bearer $_" }) }
    $want = 'name','given_name','family_name','birthdate','email','phone_number','address'
    $missing = $want | Where-Object { -not $ui.PSObject.Properties.Name.Contains($_) }
    if ($missing) { Write-Host "    MISSING: $($missing -join ', ')" -ForegroundColor Red; exit 1 }
    Write-Host "    $login ready (full §5.1 profile)." -ForegroundColor Green
}

# Both End-Users the suite might be driven with:
#   conform — the documented suite login;
#   admin   — the dev bootstrap admin, which is what you actually type on the OP form out of habit.
Seed-Profile 'conform' 'Conform1234Pass!' 'Conformance User' 'Conf' 'Ormance' 'conform@example.com' '+15551234567'
Seed-Profile 'admin'   'admin'            'Admin User'       'Ad'   'Min'     'admin@example.com'   '+15559876543'

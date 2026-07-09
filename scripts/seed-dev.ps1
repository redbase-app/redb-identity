<#
.SYNOPSIS
    Seeds development data for redb.Identity: default scopes, admin M2M client, test web app.
.DESCRIPTION
    Calls the management API via HTTP to create initial data. Idempotent — safe to re-run.
    Requires the Identity HTTP server to be running on the configured port.
.PARAMETER BaseUrl
    Base URL of the Identity HTTP server. Default: http://localhost:8080
#>
param(
    [string]$BaseUrl = "http://localhost:8080"
)

$ErrorActionPreference = "Stop"
$apiBase = "$BaseUrl/api/identity"

function Invoke-IdentityApi {
    param(
        [string]$Method,
        [string]$Path,
        [object]$Body
    )
    $uri = "$apiBase/$Path"
    $params = @{
        Method = $Method
        Uri    = $uri
        ContentType = "application/json"
    }
    if ($Body) {
        $params.Body = ($Body | ConvertTo-Json -Depth 10)
    }
    try {
        $response = Invoke-RestMethod @params
        return $response
    }
    catch {
        $status = $_.Exception.Response.StatusCode.value__
        if ($status -eq 409 -or $_.Exception.Message -match "duplicate") {
            Write-Host "  [SKIP] Already exists: $Path" -ForegroundColor Yellow
            return $null
        }
        Write-Warning "  [FAIL] $Method $Path — $($_.Exception.Message)"
        return $null
    }
}

# ── 1. Default Scopes ──
Write-Host "`n=== Creating default scopes ===" -ForegroundColor Cyan

$scopes = @(
    @{ name = "openid";         displayName = "OpenID";          description = "OpenID Connect identity" }
    @{ name = "profile";        displayName = "Profile";         description = "User profile information" }
    @{ name = "email";          displayName = "Email";           description = "User email address" }
    @{ name = "offline_access"; displayName = "Offline Access";  description = "Refresh token support" }
    @{ name = "api";            displayName = "API";             description = "General API access" }
)

foreach ($scope in $scopes) {
    Write-Host "  Creating scope: $($scope.name)..."
    Invoke-IdentityApi -Method POST -Path "scopes" -Body $scope | Out-Null
}

# ── 2. Admin M2M Client (client_credentials) ──
Write-Host "`n=== Creating admin M2M client ===" -ForegroundColor Cyan

$adminClient = @{
    clientId     = "admin-tool"
    clientSecret = "dev-secret-change-me"
    displayName  = "Admin Tool (M2M)"
    clientType   = "confidential"
    consentType  = "implicit"
    permissions  = @(
        "ept:token",
        "gt:client_credentials",
        "scp:openid", "scp:profile", "scp:email", "scp:api"
    )
}

Write-Host "  Creating client: $($adminClient.clientId)..."
Invoke-IdentityApi -Method POST -Path "applications" -Body $adminClient | Out-Null

# ── 3. Test Web App (Authorization Code + PKCE) ──
Write-Host "`n=== Creating test web app ===" -ForegroundColor Cyan

$webApp = @{
    clientId        = "test-web-app"
    displayName     = "Test Web Application"
    clientType      = "public"
    applicationType = "web"
    consentType     = "implicit"
    redirectUris    = @("http://localhost:3000/callback")
    postLogoutRedirectUris = @("http://localhost:3000")
    permissions     = @(
        "ept:token", "ept:authorization",
        "gt:authorization_code", "gt:refresh_token",
        "rst:code",
        "scp:openid", "scp:profile", "scp:email", "scp:offline_access"
    )
    requirements = @("ft:pkce")
}

Write-Host "  Creating client: $($webApp.clientId)..."
Invoke-IdentityApi -Method POST -Path "applications" -Body $webApp | Out-Null

# ── 4. Test User ──
Write-Host "`n=== Creating test user ===" -ForegroundColor Cyan

$testUser = @{
    login       = "testuser"
    password    = "Test123!"
    displayName = "Test User"
}

Write-Host "  Creating user: $($testUser.login)..."
Invoke-IdentityApi -Method POST -Path "users" -Body $testUser | Out-Null

Write-Host "`n=== Seed complete ===" -ForegroundColor Green
Write-Host @"

Ready to test:
  - Client Credentials: POST $BaseUrl/connect/token
      grant_type=client_credentials&client_id=admin-tool&client_secret=dev-secret-change-me

  - Authorization Code: GET $BaseUrl/connect/authorize
      ?client_id=test-web-app&redirect_uri=http://localhost:3000/callback
      &response_type=code&scope=openid+profile&state=random

  - Discovery: GET $BaseUrl/.well-known/openid-configuration
  - JWKS:      GET $BaseUrl/.well-known/jwks
"@

# SCIM 2.0 Enterprise User extension (RFC 7643 §4.3).
#
# This is the extension corporate provisioning actually sends: Okta, Entra ID and Workday push
# department / manager / employeeNumber on the very first sync. A provider that advertises only
# the core User schema forces them to drop that data on the floor.
#
# Asserted against the spec, not against our convenience:
#   §7      /Schemas lists the extension schema
#   §6      /ResourceTypes/User declares it under schemaExtensions (required: false)
#   §3      a resource carrying the extension lists its URN in `schemas`
#   §4.3    employeeNumber / costCenter / organization / division / department / manager
#   §4.3    manager is COMPLEX: value + $ref + displayName (displayName is provider-resolved)
#   §3.5.2  PATCH addresses extension attributes by their fully-qualified URN
#   §3.5.1  PUT is a full replace — an absent extension clears it
#
# Usage: pwsh -File demo_scim_enterprise.ps1

$BASE = if ($env:IDENTITY_BASE) { $env:IDENTITY_BASE } else { "https://127.0.0.1:5002" }
$PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
# The SCIM surface a provisioning client is pointed at: its own prefix, its own `scim` scope.
$SCIM = "$BASE/scim/v2"
# The same SCIM tree also hangs off the management prefix, for deployments that expose only that
# port. Both must answer discovery identically — a client configured on either base URL walks
# ResourceTypes and then fetches each Schema by id.
$SCIM_MGMT = "$BASE/api/v1/identity/scim/v2"
$ENT = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'

$script:Failures = 0
function Assert([string]$What, [bool]$Ok, [string]$Detail = "") {
    if ($Ok) { Write-Host "  PASS  $What" -ForegroundColor Green }
    else { $script:Failures++; Write-Host "  FAIL  $What  $Detail" -ForegroundColor Red }
}

# ── SCIM-scoped token (RFC 7644 §2 — provisioning is a client, not a human) ───────────────────
$reg = Invoke-RestMethod -Method Post "$BASE/connect/register" -ContentType "application/json" -Body (@{
    client_name = "scim-enterprise-demo"; grant_types = @("client_credentials"); scope = "scim"
} | ConvertTo-Json)
$tok = Invoke-RestMethod -Method Post "$BASE/connect/token" -ContentType "application/x-www-form-urlencoded" -Body @{
    grant_type = "client_credentials"; client_id = $reg.client_id
    client_secret = $reg.client_secret; scope = "scim"
}
$H = @{ Authorization = "Bearer $($tok.access_token)" }
$CT = "application/scim+json"

# ── 1. Discovery: the extension must be advertised, not just accepted ──────────────────────────
Write-Host "`n=== [1] discovery ===" -ForegroundColor Cyan
$schemas = Invoke-RestMethod "$SCIM/Schemas" -Headers $H
$ids = $schemas.Resources.id
Assert "/Schemas lists the Enterprise User schema (RFC 7643 §7)" ($ids -contains $ENT) `
    "got: $($ids -join ', ')"

$rt = Invoke-RestMethod "$SCIM/ResourceTypes/User" -Headers $H
Assert "/ResourceTypes/User declares it under schemaExtensions (§6)" `
    ($rt.schemaExtensions.schema -contains $ENT) "got: $($rt.schemaExtensions | ConvertTo-Json -Compress)"
Assert "the extension is NOT required — a user without a department is still a valid user" `
    (($rt.schemaExtensions | Where-Object { $_.schema -eq $ENT }).required -eq $false)

$one = Invoke-RestMethod "$SCIM/Schemas/$ENT" -Headers $H
Assert "/Schemas/{urn} returns the schema, with manager as a complex attribute (§4.3)" `
    (($one.attributes | Where-Object { $_.name -eq 'manager' }).type -eq 'complex')

# The management-prefixed SCIM tree used to register only the LIST discovery endpoints, so a client
# configured on that base URL got a 404 on the first schema it fetched. Same tree, same answers.
$mgmt = Invoke-RestMethod "$SCIM_MGMT/Schemas/$ENT" -Headers $H
Assert "the management-prefixed SCIM tree serves Schemas/{urn} too" ($mgmt.id -eq $ENT) `
    "got: $($mgmt.id)"
$mgmtRt = Invoke-RestMethod "$SCIM_MGMT/ResourceTypes/User" -Headers $H
Assert "...and ResourceTypes/{id}, with the same schemaExtensions" `
    ($mgmtRt.schemaExtensions.schema -contains $ENT) "got: $($mgmtRt.schemaExtensions | ConvertTo-Json -Compress)"

# ── 2. The manager, then the report — POST with the extension ─────────────────────────────────
Write-Host "`n=== [2] POST /Users with the extension ===" -ForegroundColor Cyan
$boss = Invoke-RestMethod -Method Post "$SCIM/Users" -Headers $H -ContentType $CT -Body (@{
    schemas = @('urn:ietf:params:scim:schemas:core:2.0:User')
    userName = "boss_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
    displayName = "Ada Lovelace"
    active = $true
} | ConvertTo-Json)
Write-Host "  manager id = $($boss.id) ($($boss.displayName))"

$body = @{
    schemas = @('urn:ietf:params:scim:schemas:core:2.0:User', $ENT)
    userName = "emp_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
    displayName = "Grace Hopper"
    active = $true
    emails = @(@{ value = "grace@example.com"; type = "work"; primary = $true })
}
$body[$ENT] = @{
    employeeNumber = "E-1906"
    costCenter     = "CC-4711"
    organization   = "redb"
    division       = "Engineering"
    department     = "Compilers"
    manager        = @{ value = $boss.id }
}
$u = Invoke-RestMethod -Method Post "$SCIM/Users" -Headers $H -ContentType $CT -Body ($body | ConvertTo-Json -Depth 6)

$e = $u.$ENT
Assert "response lists the extension URN in 'schemas' (§3)" ($u.schemas -contains $ENT) `
    "got: $($u.schemas -join ', ')"
Assert "employeeNumber round-trips" ($e.employeeNumber -eq 'E-1906') "got: $($e.employeeNumber)"
Assert "costCenter round-trips"     ($e.costCenter -eq 'CC-4711')    "got: $($e.costCenter)"
Assert "organization round-trips"   ($e.organization -eq 'redb')     "got: $($e.organization)"
Assert "division round-trips"       ($e.division -eq 'Engineering')  "got: $($e.division)"
Assert "department round-trips"     ($e.department -eq 'Compilers')  "got: $($e.department)"
Assert "manager.value = the manager's id" ($e.manager.value -eq $boss.id) "got: $($e.manager.value)"
Assert "manager.`$ref is the manager's resource URI (§4.3)" `
    ($e.manager.'$ref' -like "*/scim/v2/Users/$($boss.id)") "got: $($e.manager.'$ref')"
Assert "manager.displayName is resolved BY THE PROVIDER, not stored (§4.3 readOnly)" `
    ($e.manager.displayName -eq 'Ada Lovelace') "got: $($e.manager.displayName)"

# ── 3. GET must return the same thing POST claimed ────────────────────────────────────────────
Write-Host "`n=== [3] GET /Users/{id} ===" -ForegroundColor Cyan
$g = Invoke-RestMethod "$SCIM/Users/$($u.id)" -Headers $H
Assert "extension survives a round-trip through storage" `
    ($g.$ENT.department -eq 'Compilers' -and $g.$ENT.manager.value -eq $boss.id) `
    "got: $($g.$ENT | ConvertTo-Json -Compress)"

# ── 4. §3.5.2 PATCH by fully-qualified URN — the path a real client sends ──────────────────────
Write-Host "`n=== [4] PATCH `"$ENT`:department`" ===" -ForegroundColor Cyan
$p = Invoke-RestMethod -Method Patch "$SCIM/Users/$($u.id)" -Headers $H -ContentType $CT -Body (@{
    schemas = @('urn:ietf:params:scim:api:messages:2.0:PatchOp')
    Operations = @(
        @{ op = "replace"; path = "$ENT`:department"; value = "Runtime" },
        @{ op = "replace"; path = "$ENT`:costCenter"; value = "CC-9000" }
    )
} | ConvertTo-Json -Depth 6)
Assert "department patched via its URN path" ($p.$ENT.department -eq 'Runtime') "got: $($p.$ENT.department)"
Assert "costCenter patched via its URN path" ($p.$ENT.costCenter -eq 'CC-9000') "got: $($p.$ENT.costCenter)"
Assert "PATCH left the untouched attributes alone (employeeNumber)" `
    ($p.$ENT.employeeNumber -eq 'E-1906') "got: $($p.$ENT.employeeNumber)"

# ── 5. no-path PATCH carrying the extension as a member (the Entra ID shape) ───────────────────
Write-Host "`n=== [5] no-path PATCH (Entra ID shape) ===" -ForegroundColor Cyan
$val = @{ }
$val[$ENT] = @{ division = "Platform" }
$p = Invoke-RestMethod -Method Patch "$SCIM/Users/$($u.id)" -Headers $H -ContentType $CT -Body (@{
    schemas = @('urn:ietf:params:scim:api:messages:2.0:PatchOp')
    Operations = @(@{ op = "replace"; value = $val })
} | ConvertTo-Json -Depth 6)
Assert "division updated from a no-path partial resource" ($p.$ENT.division -eq 'Platform') `
    "got: $($p.$ENT.division)"
Assert "and it still did not touch department" ($p.$ENT.department -eq 'Runtime') `
    "got: $($p.$ENT.department)"

# ── 6. §3.5.2 remove ──────────────────────────────────────────────────────────────────────────
Write-Host "`n=== [6] PATCH remove manager ===" -ForegroundColor Cyan
$p = Invoke-RestMethod -Method Patch "$SCIM/Users/$($u.id)" -Headers $H -ContentType $CT -Body (@{
    schemas = @('urn:ietf:params:scim:api:messages:2.0:PatchOp')
    Operations = @(@{ op = "remove"; path = "$ENT`:manager" })
} | ConvertTo-Json -Depth 6)
Assert "manager removed" ($null -eq $p.$ENT.manager) "got: $($p.$ENT.manager | ConvertTo-Json -Compress)"
Assert "the rest of the extension survived the removal" ($p.$ENT.department -eq 'Runtime')

# ── 7. §3.5.1 PUT is a FULL replace — an absent extension means the user has none ──────────────
Write-Host "`n=== [7] PUT without the extension ===" -ForegroundColor Cyan
$r = Invoke-RestMethod -Method Put "$SCIM/Users/$($u.id)" -Headers $H -ContentType $CT -Body (@{
    schemas = @('urn:ietf:params:scim:schemas:core:2.0:User')
    id = $u.id; userName = $u.userName; displayName = "Grace Hopper"; active = $true
} | ConvertTo-Json)
Assert "PUT cleared the extension — a full replace replaces fully (§3.5.1)" `
    ($null -eq $r.$ENT) "got: $($r.$ENT | ConvertTo-Json -Compress)"
Assert "and the URN is no longer advertised in 'schemas'" `
    (-not ($r.schemas -contains $ENT)) "got: $($r.schemas -join ', ')"

# ── cleanup ───────────────────────────────────────────────────────────────────────────────────
Invoke-RestMethod -Method Delete "$SCIM/Users/$($u.id)" -Headers $H | Out-Null
Invoke-RestMethod -Method Delete "$SCIM/Users/$($boss.id)" -Headers $H | Out-Null

Write-Host ""
if ($script:Failures -eq 0) {
    Write-Host "OK - SCIM Enterprise User extension (RFC 7643 4.3): all assertions passed" -ForegroundColor Green
    exit 0
}
Write-Host "FAIL($script:Failures) - see above" -ForegroundColor Red
exit 1

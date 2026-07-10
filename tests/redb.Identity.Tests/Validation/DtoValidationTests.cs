using redb.Identity.Contracts.Applications;
using redb.Identity.Contracts.Groups;
using redb.Identity.Contracts.Scim;
using redb.Identity.Contracts.Scopes;
using redb.Identity.Contracts.Users;
using redb.Identity.Contracts.Validation;
using redb.Identity.Http.Controllers;
using Xunit;

namespace redb.Identity.Tests.Validation;

/// <summary>
/// E6 — Validation: confirms that DataAnnotations on request DTOs produce a uniform
/// <c>{ error = "invalid_request" }</c> problem for the management API and a
/// <see cref="ScimError"/> with HTTP-400 semantics for SCIM endpoints.
/// </summary>
public class DtoValidationTests
{
    // ── Management API (RequestValidator) ────────────────────────────────────

    [Fact]
    public void RequestValidator_NullRequest_ReturnsInvalidRequestProblem()
    {
        var problem = RequestValidator.Validate(null);
        Assert.NotNull(problem);
        var error = problem!.GetType().GetProperty("error")?.GetValue(problem) as string;
        Assert.Equal("validation_error", error);
    }

    [Fact]
    public void CreateApplication_MissingClientId_FailsValidation()
    {
        var dto = new CreateApplicationRequest { ClientId = string.Empty };
        var problem = RequestValidator.Validate(dto);
        Assert.NotNull(problem);
    }

    [Fact]
    public void CreateApplication_ValidClientId_Passes()
    {
        var dto = new CreateApplicationRequest { ClientId = "my-client" };
        Assert.Null(RequestValidator.Validate(dto));
    }

    [Fact]
    public void UpdateApplication_MissingId_FailsValidation()
    {
        var dto = new UpdateApplicationRequest { Id = string.Empty };
        Assert.NotNull(RequestValidator.Validate(dto));
    }

    [Fact]
    public void CreateGroup_EmptyName_FailsValidation()
    {
        var dto = new CreateGroupRequest { Name = string.Empty };
        Assert.NotNull(RequestValidator.Validate(dto));
    }

    [Fact]
    public void CreateGroup_NameAtBoundary_Passes()
    {
        var dto = new CreateGroupRequest { Name = "g" };
        Assert.Null(RequestValidator.Validate(dto));
    }

    [Fact]
    public void AddMember_ZeroUserId_FailsValidation()
    {
        var dto = new AddMemberRequest { UserId = 0 };
        Assert.NotNull(RequestValidator.Validate(dto));
    }

    [Fact]
    public void UpdateMember_EmptyRole_FailsValidation()
    {
        var dto = new UpdateMemberRequest { Role = string.Empty };
        Assert.NotNull(RequestValidator.Validate(dto));
    }

    [Fact]
    public void MoveGroup_ZeroParentId_FailsValidation()
    {
        var dto = new MoveGroupRequest { NewParentGroupId = 0 };
        Assert.NotNull(RequestValidator.Validate(dto));
    }

    [Fact]
    public void CreateScope_EmptyName_FailsValidation()
    {
        var dto = new CreateScopeRequest { Name = string.Empty };
        Assert.NotNull(RequestValidator.Validate(dto));
    }

    [Fact]
    public void UpdateScope_EmptyId_FailsValidation()
    {
        var dto = new UpdateScopeRequest { Id = string.Empty };
        Assert.NotNull(RequestValidator.Validate(dto));
    }

    [Fact]
    public void CreateUser_EmptyLogin_FailsValidation()
    {
        var dto = new CreateUserRequest { Login = string.Empty, Password = "secret" };
        var problem = RequestValidator.Validate(dto);
        Assert.NotNull(problem);
    }

    [Fact]
    public void MfaConfirm_EmptyCode_FailsValidation()
    {
        var dto = new MfaConfirmRequest { UserId = 1, Code = string.Empty };
        Assert.NotNull(RequestValidator.Validate(dto));
    }

    [Fact]
    public void MfaConfirm_ZeroUserId_FailsValidation()
    {
        var dto = new MfaConfirmRequest { UserId = 0, Code = "123456" };
        Assert.NotNull(RequestValidator.Validate(dto));
    }

    [Fact]
    public void MfaOtpSetup_EmptyDestination_FailsValidation()
    {
        var dto = new MfaOtpSetupRequest { UserId = 1, Destination = string.Empty };
        Assert.NotNull(RequestValidator.Validate(dto));
    }

    [Fact]
    public void MfaOtpConfirm_EmptyMfaState_FailsValidation()
    {
        var dto = new MfaOtpConfirmRequest { UserId = 1, Code = "123456", MfaState = string.Empty };
        Assert.NotNull(RequestValidator.Validate(dto));
    }

    // ── SCIM (ScimRequestValidator) ──────────────────────────────────────────

    [Fact]
    public void ScimRequestValidator_NullRequest_ReturnsScimError400()
    {
        var err = ScimRequestValidator.Validate(null);
        Assert.NotNull(err);
        Assert.Equal("400", err!.Status);
        Assert.Equal("invalidValue", err.ScimType);
    }

    [Fact]
    public void ScimRequestValidator_ValidScimUser_Passes()
    {
        var user = new ScimUser { UserName = "alice" };
        Assert.Null(ScimRequestValidator.Validate(user));
    }
}

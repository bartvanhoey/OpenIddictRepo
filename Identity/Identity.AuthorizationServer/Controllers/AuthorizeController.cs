using System.Collections.Immutable;
using System.Security.Claims;
using System.Web;
using Identity.AuthorizationServer.Data;
using Identity.AuthorizationServer.Services;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace Identity.AuthorizationServer.Controllers;

public class AuthorizationController : Controller
{
    // private static ClaimsIdentity _identity = new();
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AuthService _authService;


    public AuthorizationController(IOpenIddictApplicationManager applicationManager,
        IOpenIddictScopeManager scopeManager,
        SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, AuthService authService)
    {
        _applicationManager = applicationManager;
        _scopeManager = scopeManager;
        _signInManager = signInManager;
        _userManager = userManager;
        _authService = authService;
    }

    [HttpPost("~/connect/token"), Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest();
        if (request == null) return BadRequest("The request is missing.");
        if (request.IsClientCredentialsGrantType()) return await ProcessClientCredentialsGrantType(request);
        if (request.IsPasswordGrantType()) return await ProcessPasswordGrantType(request);
        throw new NotImplementedException("The specified grant is not implemented.");
    }

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ??
                          throw new InvalidOperationException(
                              "Details concerning the calling client application cannot be found.");

        if (await _applicationManager.GetConsentTypeAsync(application) != OpenIddictConstants.ConsentTypes.Explicit)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] =
                        OpenIddictConstants.Errors.InvalidClient,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "Only clients with explicit consent type are allowed."
                }));
        }

        var parameters = _authService.ParseOAuthParameters(HttpContext,
            new List<string> { OpenIddictConstants.Parameters.Prompt });

        var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        if (!_authService.IsAuthenticated(result, request))
        {
            return Challenge(properties: new AuthenticationProperties
            {
                RedirectUri = _authService.BuildRedirectUrl(HttpContext.Request, parameters)
            }, new[] { CookieAuthenticationDefaults.AuthenticationScheme });
        }

        if (request.HasPromptValue(OpenIddictConstants.PromptValues.Login))
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return Challenge(properties: new AuthenticationProperties
            {
                RedirectUri = _authService.BuildRedirectUrl(HttpContext.Request, parameters)
            }, new[] { CookieAuthenticationDefaults.AuthenticationScheme });
        }

        var consentClaim = result.Principal.GetClaim(Consts.ConsentNaming);

        // it might be extended in a way that consent claim will contain list of allowed client ids.
        if (consentClaim != Consts.GrantAccessValue ||
            request.HasPromptValue(OpenIddictConstants.PromptValues.Consent))
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            var returnUrl = HttpUtility.UrlEncode(_authService.BuildRedirectUrl(HttpContext.Request, parameters));
            var consentRedirectUrl = $"/Consent?returnUrl={returnUrl}";

            return Redirect(consentRedirectUrl);
        }

        var userId = result.Principal.FindFirst(ClaimTypes.Email)!.Value;

        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: OpenIddictConstants.Claims.Name,
            roleType: OpenIddictConstants.Claims.Role);

        identity.SetClaim(OpenIddictConstants.Claims.Subject, userId)
            .SetClaim(OpenIddictConstants.Claims.Email, userId)
            .SetClaim(OpenIddictConstants.Claims.Name, userId)
            .SetClaims(OpenIddictConstants.Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());

        identity.SetScopes(request.GetScopes());
        identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
        identity.SetDestinations(c => AuthService.GetDestinations(identity, c));

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IActionResult> ProcessPasswordGrantType(OpenIddictRequest request)
    {
        // if client_id or client_secret are invalid, this action won't be invoked.
        try
        {
            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                OpenIddictConstants.Claims.Name, OpenIddictConstants.Claims.Role);
            AuthenticationProperties properties = new();

            var user = await _userManager.FindByNameAsync(request.Username ?? throw new InvalidOperationException());
            if (user == null)
                return BadRequest(new OpenIddictResponse
                {
                    Error = OpenIddictConstants.Errors.InvalidGrant,
                    ErrorDescription = "User does not exist"
                });

            // Check that the user can sign in and is not locked out.
            // If two-factor authentication is supported, it would also be appropriate to check that 2FA is enabled for the user
            if (!await _signInManager.CanSignInAsync(user) ||
                (_userManager.SupportsUserLockout && await _userManager.IsLockedOutAsync(user)))
            {
                // Return bad request is the user can't sign in
                return BadRequest(new OpenIddictResponse
                {
                    Error = OpenIddictConstants.Errors.InvalidGrant,
                    ErrorDescription = "The specified user cannot sign in."
                });
            }

            // Validate the username/password parameters and ensure the account is not locked out.
            var result = await _signInManager.PasswordSignInAsync(user.UserName, request.Password,
                false, lockoutOnFailure: false);
            if (!result.Succeeded)
            {
                if (result.IsNotAllowed)
                {
                    return BadRequest(new OpenIddictResponse
                    {
                        Error = OpenIddictConstants.Errors.InvalidGrant,
                        ErrorDescription = "User not allowed to login. Please confirm your email"
                    });
                }

                if (result.RequiresTwoFactor)
                {
                    return BadRequest(new OpenIddictResponse
                    {
                        Error = OpenIddictConstants.Errors.InvalidGrant,
                        ErrorDescription = "User requires 2F authentication"
                    });
                }

                if (result.IsLockedOut)
                {
                    return BadRequest(new OpenIddictResponse
                    {
                        Error = OpenIddictConstants.Errors.InvalidGrant,
                        ErrorDescription = "User is locked out"
                    });
                }

                return BadRequest(new OpenIddictResponse
                {
                    Error = OpenIddictConstants.Errors.InvalidGrant,
                    ErrorDescription = "Username or password is incorrect"
                });
            }

            // The user is now validated, so reset lockout counts, if necessary
            if (_userManager.SupportsUserLockout) { await _userManager.ResetAccessFailedCountAsync(user); }

            //// Getting scopes from user parameters (TokenViewModel) and adding in Identity 
            identity.SetScopes(request.GetScopes());

            // Getting scopes from user parameters (TokenViewModel)
            // Checking in OpenIddictScopes tables for matching resources
            // Adding in Identity
            identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

            // Add Custom claims => sub claims is mandatory
            identity.AddClaim(new Claim(OpenIddictConstants.Claims.Subject, user.Id));
            identity.AddClaim(new Claim(OpenIddictConstants.Claims.PreferredUsername, user.Email ?? user.UserName));
            identity.AddClaim(new Claim(OpenIddictConstants.Claims.Audience, "Resourse"));
            identity.AddClaim(new Claim("some-claim", "some-value"));

            // Setting destinations of claims i.e. identity token or access token
            
            // When using this statement, custom claims not included in AccessToken
             // identity.SetDestinations(x => GetDestinations(x, identity));
 
            identity.SetDestinations(static claim => claim.Type switch
            {
                // Allow the "name" claim to be stored in both the access and identity tokens
                // when the "profile" scope was granted (by calling principal.SetScopes(...)).
                OpenIddictConstants.Claims.Name when (claim.Subject ?? throw new InvalidOperationException()).HasScope(
                        OpenIddictConstants.Permissions.Scopes.Profile)
                    => [OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken],

                // Otherwise, only store the claim in the access tokens.
                _ => [OpenIddictConstants.Destinations.AccessToken]
            });

            // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
            var signInResult = SignIn(new ClaimsPrincipal(identity), properties,
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            return signInResult;
        }
        catch (Exception ex)
        {
            return BadRequest(new OpenIddictResponse()
            {
                Error = OpenIddictConstants.Errors.ServerError,
                ErrorDescription = "Invalid login attempt"
            });
        }
    }

    private async Task<IActionResult> ProcessClientCredentialsGrantType(OpenIddictRequest request)
    {
        // Note: the client credentials are automatically validated by OpenIddict:
        // if client_id or client_secret are invalid, this action won't be invoked.
        var application =
            await _applicationManager.FindByClientIdAsync(request.ClientId ?? throw new InvalidOperationException()) ??
            throw new InvalidOperationException("The application cannot be found.");
        // Create a new ClaimsIdentity containing the claims that will be used to create an id_token, a token or a code.
        var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType,
            OpenIddictConstants.Claims.Name, OpenIddictConstants.Claims.Role);
        // Use the client_id as the subject identifier.
        identity.SetClaim(OpenIddictConstants.Claims.Subject, await _applicationManager.GetClientIdAsync(application));
        identity.SetClaim(OpenIddictConstants.Claims.Name, await _applicationManager.GetDisplayNameAsync(application));
        identity.AddClaim(new Claim(OpenIddictConstants.Claims.Audience, "Resourse"));
        identity.AddClaim(new Claim("some-claim", "some-value"));
        identity.SetDestinations(static claim => claim.Type switch
        {
            // Allow the "name" claim to be stored in both the access and identity tokens
            // when the "profile" scope was granted (by calling principal.SetScopes(...)).
            OpenIddictConstants.Claims.Name when (claim.Subject ?? throw new InvalidOperationException()).HasScope(
                    OpenIddictConstants.Permissions.Scopes.Profile)
                => [OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken],

            // Otherwise, only store the claim in the access tokens.
            _ => [OpenIddictConstants.Destinations.AccessToken]
        });
        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static List<string> GetDestinations(Claim claim, ClaimsIdentity identity)
    {
        var destinations = new List<string>();
        if (claim.Type is not (OpenIddictConstants.Claims.Name or OpenIddictConstants.Claims.Email
            or OpenIddictConstants.Claims.Subject)) return destinations;
        destinations.Add(OpenIddictConstants.Destinations.AccessToken);
        if (identity.HasScope(OpenIddictConstants.Scopes.OpenId))
            destinations.Add(OpenIddictConstants.Destinations.IdentityToken);
        return destinations;
    }
}
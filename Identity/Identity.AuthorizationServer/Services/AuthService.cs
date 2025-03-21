using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;

namespace Identity.AuthorizationServer.Services;

public class AuthService
{

    public string BuildRedirectUrl(HttpRequest request, IDictionary<string, StringValues> parameters)
    {
        var url = request.PathBase + request.Path + QueryString.Create(parameters);
        return url;
    }
    
    public bool IsAuthenticated(AuthenticateResult? result, OpenIddictRequest request)
    {
        if (result is { Succeeded: false }) { return false; }

        if (!request.MaxAge.HasValue || result?.Properties == null) return true;
        
        var maxAgeSeconds = TimeSpan.FromSeconds(request.MaxAge.Value);
        var expired = !result.Properties.IssuedUtc.HasValue 
                      || DateTimeOffset.UtcNow - result.Properties.IssuedUtc > maxAgeSeconds;
        return !expired;
    }
    
    public IDictionary<string, StringValues> ParseOAuthParameters(HttpContext httpContext, List<string?> excluding = null) =>
        httpContext.Request.HasFormContentType
            ? httpContext.Request.Form.Where(parameter => !excluding.Contains(parameter.Key))
                .ToDictionary()
            : httpContext.Request.Query.Where(parameter => !excluding.Contains(parameter.Key))
                .ToDictionary();

    public static List<string> GetDestinations(ClaimsIdentity identity, Claim claim)
    {
        var destinations = new List<string>();

        if (claim.Type is OpenIddictConstants.Claims.Name or OpenIddictConstants.Claims.Email)
        {
            destinations.Add(OpenIddictConstants.Destinations.AccessToken);

            if (identity.HasScope(OpenIddictConstants.Scopes.OpenId))
            {
                destinations.Add(OpenIddictConstants.Destinations.IdentityToken);
            }
        }

        return destinations;
    }
    
}
using Identity.AuthorizationServer.Data;

namespace Identity.AuthorizationServer.ServiceRegistration;

public static class OpenIddictRegistration
{
    public static void SetupOpenIddict(this WebApplicationBuilder builder) =>
        builder.Services.AddOpenIddict()
            .AddCore(coreOptions =>
            {
                coreOptions.UseEntityFrameworkCore()
                    .UseDbContext<ApplicationDbContext>();
            })
            .AddServer(options =>
            {
                options.SetAuthorizationEndpointUris("/connect/authorize");
                options.SetTokenEndpointUris("connect/token");
        
                options.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange();
                options.AllowClientCredentialsFlow().AllowRefreshTokenFlow();
                options.AllowPasswordFlow().AllowRefreshTokenFlow();

                // Encryption and signing of tokens
                options
                    .AddDevelopmentEncryptionCertificate()
                    .AddDevelopmentSigningCertificate()
                    .DisableAccessTokenEncryption();

                // Register the ASP.NET Core host and configure the ASP.NET Core options.
                options.UseAspNetCore()
                    .EnableTokenEndpointPassthrough()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableEndSessionEndpointPassthrough()
                    .DisableTransportSecurityRequirement();
                
                
            });
}
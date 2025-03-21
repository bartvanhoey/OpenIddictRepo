# OpenIddict AuthServer

## Create a new Web API project

## Install required packages

```bash
Microsoft.EntityFrameworkCore  Version 9.0.3 
Microsoft.EntityFrameworkCore.Design  Version 9.0.3 
Microsoft.EntityFrameworkCore.Tools  Version 9.0.3 
Microsoft.EntityFrameworkCore.SqlServer  Version 9.0.3 
Microsoft.AspNetCore.Identity.EntityFrameworkCore  Version 9.0.3 
System.Linq.Async  Version 6.0.1 

OpenIddict  Version 6.1.1 
OpenIddict.Abstractions  Version 6.1.1 
OpenIddict.Core  Version 6.1.1 
OpenIddict.EntityFrameworkCore  Version 6.1.1 
OpenIddict.Server.AspNetCore  Version 6.1.1 
```

```csharp
public static void SetupOpenIddict(this WebApplicationBuilder builder) =>
        builder.Services.AddOpenIddict()
            .AddCore(coreOptions =>
            {
                coreOptions.UseEntityFrameworkCore()
                    .UseDbContext<ApplicationDbContext>();
            })
            .AddServer(options =>
            {
                options.SetTokenEndpointUris("connect/token");
        
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
```
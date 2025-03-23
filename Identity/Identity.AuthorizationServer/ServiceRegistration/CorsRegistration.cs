using static System.Console;

namespace Identity.AuthorizationServer.ServiceRegistration;

public static class CorsRegistration
{
    public static void AddCorsPolicy(this WebApplicationBuilder builder)
    {
        builder.Services.AddCors(options =>
        {
            options.AddPolicy("CorsPolicy", policy =>
            {
                policy
                    .WithOrigins(["https://localhost:7152"])
                    .SetIsOriginAllowed(_ => true)
                    .AllowAnyMethod()
                    .AllowAnyHeader()
                    .AllowCredentials();
            });
        });
    }
}
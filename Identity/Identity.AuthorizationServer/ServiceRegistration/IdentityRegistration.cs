using Identity.AuthorizationServer.Data;
using Microsoft.AspNetCore.Identity;

namespace Identity.AuthorizationServer.ServiceRegistration;

public static class IdentityRegistration
{
    public static void SetupIdentity(this WebApplicationBuilder builder) =>
        builder.Services.AddIdentity<ApplicationUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>()
            // .AddSignInManager()
            
            .AddDefaultUI()
            .AddDefaultTokenProviders();
}
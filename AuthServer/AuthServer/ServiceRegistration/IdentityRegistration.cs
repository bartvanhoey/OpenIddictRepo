using AuthServer.Data;
using Microsoft.AspNetCore.Identity;

namespace AuthServer.ServiceRegistration;

public static class IdentityRegistration
{
    public static void SetupIdentity(this WebApplicationBuilder builder) =>
        builder.Services.AddIdentity<ApplicationUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();
}
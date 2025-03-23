using Identity.AuthorizationServer.Data;
using Microsoft.EntityFrameworkCore;

namespace Identity.AuthorizationServer.ServiceRegistration;

public static class DatabaseRegistration
{
    public static void SetupDatabase(this WebApplicationBuilder builder)
    {
        var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ??
                               throw new InvalidOperationException("Connection string not found");

        builder.Services.AddDbContext<ApplicationDbContext>(o =>
        {
            o.UseSqlServer(connectionString);
            o.UseOpenIddict();
        });
        

    }
}
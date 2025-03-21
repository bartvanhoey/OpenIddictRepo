using AuthServer.Data;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.ServiceRegistration;

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
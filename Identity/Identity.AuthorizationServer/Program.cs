using Identity.AuthorizationServer.Data;
using Identity.AuthorizationServer.ServiceRegistration;
using Identity.AuthorizationServer.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Identity.AuthorizationServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            
            builder.Services.AddDatabaseDeveloperPageExceptionFilter();

            builder.Services.AddControllers();
            
            builder.SetupDatabase();

            builder.SetupIdentity();    

            builder.SetupOpenIddict();
            
            builder.AddCorsPolicy();

            // builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            //     .AddCookie(options => { options.LoginPath = "/authenticate"; });

            builder.Services.AddTransient<AuthService>();
            builder.Services.AddTransient<ClientSeeder>();
            
            
            builder.Services.AddRazorPages();

            var app = builder.Build();
            
            
            using (var scope = app.Services.CreateScope())
            {
                var clientSeeder = scope.ServiceProvider.GetRequiredService<ClientSeeder>();
                clientSeeder.AddTestClient().GetAwaiter().GetResult();
                clientSeeder.AddPasswordClient().GetAwaiter().GetResult();
                clientSeeder.AddOidcDebuggerClient().GetAwaiter().GetResult();
                clientSeeder.AddWebClient().GetAwaiter().GetResult();
                clientSeeder.AddReactClient().GetAwaiter().GetResult();
                clientSeeder.AddScopes().GetAwaiter().GetResult();
            }

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseMigrationsEndPoint();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();
            
            app.MapControllers();

            app.MapStaticAssets();
            app.MapRazorPages()
               .WithStaticAssets();
            
            app.UseCors(x => x.AllowAnyOrigin()
                .AllowAnyHeader()
                .AllowAnyMethod()
            );

            app.Run();
        }
    }
}

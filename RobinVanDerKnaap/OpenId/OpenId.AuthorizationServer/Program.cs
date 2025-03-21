using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using OpenId.AuthorizationServer.Data;
using OpenId.AuthorizationServer.Services;

namespace OpenId.AuthorizationServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddRazorPages();
            builder.Services.AddControllers();

            builder.Services.AddDbContext<ApplicationDbContext>(o =>
            {
                o.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
                o.UseOpenIddict();
            });

            builder.Services.AddOpenIddict()
                .AddCore(options =>
                {
                    options.UseEntityFrameworkCore()
                        .UseDbContext<ApplicationDbContext>();
                })
                .AddServer(options =>
                {
                    options
                        .SetAuthorizationEndpointUris("connect/authorize")
                        .SetEndSessionEndpointUris("connect/logout")
                        .SetTokenEndpointUris("connect/token")
                        .SetUserInfoEndpointUris("connect/userinfo");

                    options.AllowAuthorizationCodeFlow();
                    options.AllowClientCredentialsFlow();

                    options.AddDevelopmentEncryptionCertificate().AddDevelopmentSigningCertificate();

                    options.UseAspNetCore()
                        .EnableEndSessionEndpointPassthrough()
                        .EnableAuthorizationEndpointPassthrough()
                        .EnableUserInfoEndpointPassthrough()
                        .EnableTokenEndpointPassthrough();
                })
                .AddValidation(options =>
                {
                    options.UseLocalServer();
                    options.UseAspNetCore();
                });

            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options => { options.LoginPath = "/authenticate"; });

            builder.Services.AddTransient<AuthService>();
            builder.Services.AddTransient<ClientsSeeder>();


            var app = builder.Build();


            using (var scope = app.Services.CreateScope())
            {
                var seeder = scope.ServiceProvider.GetRequiredService<ClientsSeeder>();

                seeder.AddOidcDebuggerClient().GetAwaiter().GetResult();
                seeder.AddWebClient().GetAwaiter().GetResult();
                seeder.AddReactClient().GetAwaiter().GetResult();

                seeder.AddScopes().GetAwaiter().GetResult();
            }

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapStaticAssets();

            app.MapControllers();
            app.MapRazorPages()
                .WithStaticAssets();

            app.Run();
        }
    }
}
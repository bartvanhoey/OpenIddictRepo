using AuthServer;
using AuthServer.ServiceRegistration;
using Microsoft.AspNetCore.Authentication.Cookies;
using OpenId.AuthorizationServer.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

builder.Services.AddOpenApi();

builder.SetupDatabase();

builder.SetupIdentity();    

builder.SetupOpenIddict();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options => { options.LoginPath = "/authenticate"; });

builder.Services.AddTransient<AuthService>();
builder.Services.AddTransient<ClientSeeder>();

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

if (app.Environment.IsDevelopment()) { app.MapOpenApi(); }

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();


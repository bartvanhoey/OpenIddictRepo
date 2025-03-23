using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Identity.Wasm;
using Identity.Wasm.Services.Register;

using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Net9Auth.BlazorWasm;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddScoped<IdentityRedirectManager>();

builder.Services.AddScoped<IRegisterService, RegisterService>();


// builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });

builder.Services.AddHttpClient("AuthorityHttpClient",
        client =>
        {
            client.BaseAddress = new Uri("https://localhost:7000/");
        });
    // .AddHttpMessageHandler<CustomAuthenticationHandler>();




await builder.Build().RunAsync();
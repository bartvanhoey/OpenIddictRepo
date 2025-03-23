using Identity.Shared.Models;
using Identity.Wasm.Pages.Base;
using Identity.Wasm.Services.Register;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using Net9Auth.BlazorWasm;

namespace Identity.Wasm.Pages.Authentication.Register;

public class RegisterBase : CoreComponentBase
{
    [Parameter] public string? ReturnUrlParameter { get; set; }
    [Inject] protected ILogger<RegisterBase>? Logger { get; set; }
    [Inject] protected IRegisterService? RegisterService { get; set; }
    [Inject] public IdentityRedirectManager? RedirectManager { get; set; }
    [SupplyParameterFromForm] protected RegisterInputModel Input { get; set; } = new();
    [SupplyParameterFromQuery] protected string? ReturnUrl { get; set; }
    protected string? Message { get; private set; }

    public async Task RegisterUserAsync(EditContext editContext)
    {
        Message = "";
        if (RegisterService == null) return;

        var result = await RegisterService.RegisterAsync(Input);
        if (result is { Success: true })
        {
            Logger?.LogInformation("User created a new account with password");
            RedirectManager?.RedirectTo($"account/emailsent?token={result.Token}");
        }
        else
            Message = "Error: Could not register the user.";
    }
}
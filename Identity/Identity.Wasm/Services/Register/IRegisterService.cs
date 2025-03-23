using Identity.Shared.Models;

namespace Identity.Wasm.Services.Register;

public interface IRegisterService
{
    Task<RegisterResult> RegisterAsync(RegisterInputModel input);
}
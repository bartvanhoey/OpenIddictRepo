using System.Net.Http.Json;
using Identity.Shared.Models;

namespace Identity.Wasm.Services.Register;

public class RegisterService(IHttpClientFactory httpClientFactory) : IRegisterService
{
    private readonly HttpClient _httpclient = httpClientFactory.CreateClient("AuthorityHttpClient");
    
    public async Task<RegisterResult> RegisterAsync(RegisterInputModel input)
    {
        var response = await _httpclient.PostAsJsonAsync("api/registration", input);
        return response.IsSuccessStatusCode ? new RegisterResult { Success = true } : new RegisterResult {Success = false};
    }
}
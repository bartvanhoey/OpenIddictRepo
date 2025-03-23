namespace Identity.Wasm.Services.Register;

public class RegisterResult
{
    public bool Success { get; set; }
    public bool Failure => !Success;
    public string? Token { get; } 
}
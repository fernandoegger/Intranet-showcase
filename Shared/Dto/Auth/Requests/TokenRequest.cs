namespace Shared.Dto.Auth.Requests;

public class TokenRequest
{
    public string AccessToken { get; set; } = null!;
    public string RefreshToken { get; set; } = null!;
}
namespace Shared.Dto.Requests;

public class TokenReponse
{
    public string AccessToken { get; set; } = null!;
    public string RefreshToken { get; set; } = null!;
}
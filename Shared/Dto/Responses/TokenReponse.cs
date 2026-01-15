namespace Shared.Dto.Responses;

public class TokenReponse
{
    public string AccessToken { get; set; } = null!;
    public string RefreshToken { get; set; } = null!;
}
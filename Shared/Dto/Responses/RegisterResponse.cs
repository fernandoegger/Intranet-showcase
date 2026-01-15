namespace Shared.Dto.Responses;

public class RegisterResponse
{
    public required string UserId { get; set; }
    public required string EmailConfirmationToken { get; set; }
}
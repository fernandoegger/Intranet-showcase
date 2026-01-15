using Api.Data.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using Shared;
using Shared.Dto.Responses;

namespace Api.Controllers;

[ApiController]
[Route("api")]
public class AuthController(
    UserManager<User> userManager,
    SignInManager<User> signInManager,
    IConfiguration configuration)
    : ControllerBase
{
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] Shared.Dto.Requests.RegisterRequest registerRequest)
    {
        var user = new User
        {
            UserName = registerRequest.Email,
            Email = registerRequest.Email,
            Name = registerRequest.Name
        };

        await userManager.CreateAsync(user, registerRequest.Password);
        
        var token = await userManager.GenerateEmailConfirmationTokenAsync(user);
        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
        
        var registerResponse = new Shared.Dto.Responses.RegisterResponse
        {
            UserId = user.Id,
            EmailConfirmationToken = encodedToken
        };

        return Ok(ApiResponse<RegisterResponse>.Success(registerResponse,"Registro bem-sucedido. Verifique seu e-mail para confirmar a conta."));
    }
}
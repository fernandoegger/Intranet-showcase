using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Api.Data.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using Microsoft.IdentityModel.Tokens;
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

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] Shared.Dto.Requests.LoginRequest loginRequest)
    {
        var user = await userManager.FindByEmailAsync(loginRequest.Email);
        
        if(user is null)
            return Unauthorized(ApiResponse<object>.Error("E-mail ou senha inválidos."));
        
        var passwordCheck = await signInManager.CheckPasswordSignInAsync(user, loginRequest.Password, false);
        
        if(!passwordCheck.Succeeded)
            return Unauthorized(ApiResponse<object>.Error("E-mail ou senha inválidos."));
        
        if(!user.EmailConfirmed)
            return Unauthorized(ApiResponse<object>.Error("E-mail não confirmado. Por favor, confirme seu e-mail antes de fazer login."));
        
        var acessToken = await GenerateJwtToken(user);
        var refreshToken = GenerateRefreshToken();
        
        user.RefreshTokenExpiryTime = loginRequest.RememberMe
            ? DateTime.UtcNow.AddDays(30)
            : DateTime.UtcNow.AddHours(8);
        
        user.RefreshToken = refreshToken;
        await userManager.UpdateAsync(user);
        
        var tokenResponse = new Shared.Dto.Responses.TokenReponse
        {
            AccessToken = acessToken,
            RefreshToken = refreshToken
        };
        
        return Ok(ApiResponse<TokenReponse>.Success(tokenResponse, "Login realizado com sucesso."));
    }
    
    private async Task<string> GenerateJwtToken(User user)
    {
        var userRoles = await userManager.GetRolesAsync(user);
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email!),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(ClaimTypes.Name, user.UserName!)
        };
        
        claims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        
        var token = new JwtSecurityToken(
            issuer: configuration["JWT:ValidIssuer"],
            audience: configuration["JWT:ValidAudience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(15),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    
    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
}
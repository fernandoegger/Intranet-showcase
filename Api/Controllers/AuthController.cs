using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Api.Data.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Shared.Dto.Requests;
using Shared.Dto.Responses;

namespace Api.Controllers;

[ApiController]
[Route("api")]
public class AuthController(
    UserManager<User> userManager,
    SignInManager<User> signInManager,
    IEmailSender<User> emailSender,
    IConfiguration configuration)
    : ControllerBase
{
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest registerRequest)
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
        
        var callbackUrl =
            $"{configuration["FrontendUrl:ConfirmEmailUrl"]}?userId={user.Id}&token={encodedToken}";
        
        await emailSender.SendConfirmationLinkAsync(user, user.Email, callbackUrl);
        
        return Ok(ApiResponse<object>.Success(null, "Registro bem-sucedido. Verifique seu e-mail para confirmar a conta."));
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest loginRequest)
    {
        var user = await userManager.FindByEmailAsync(loginRequest.Email);

        if (user is null)
            return Unauthorized(ApiResponse<object>.Error("E-mail ou senha inválidos."));

        var passwordCheck = await userManager.CheckPasswordAsync(user, loginRequest.Password);

        if (!passwordCheck)
            return Unauthorized(ApiResponse<object>.Error("E-mail ou senha inválidos."));

        if (!user.EmailConfirmed)
            return Unauthorized(
                ApiResponse<object>.Error(
                    "E-mail não confirmado. Por favor, confirme seu e-mail antes de fazer login."));

        var signChecker = await signInManager.CheckPasswordSignInAsync(user, loginRequest.Password, false);

        if (!signChecker.Succeeded)
            return Unauthorized(ApiResponse<object>.Error("E-mail ou senha inválidos."));

        var acessToken = await GenerateJwtToken(user);
        var refreshToken = GenerateRefreshToken();

        user.RefreshTokenExpiryTime = loginRequest.RememberMe
            ? DateTime.UtcNow.AddDays(30)
            : DateTime.UtcNow.AddHours(8);

        user.RefreshToken = refreshToken;
        await userManager.UpdateAsync(user);

        var tokenResponse = new TokenResponse
        {
            AccessToken = acessToken,
            RefreshToken = refreshToken
        };

        return Ok(ApiResponse<TokenResponse>.Success(tokenResponse, "Login realizado com sucesso."));
    }

    [HttpGet("confirm-email")]
    public async Task<IActionResult> ConfirmEmail(string userId, string token)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(token))
            return BadRequest(ApiResponse<object>.Error("ID de usuário e token são necessários."));

        var user = await userManager.FindByIdAsync(userId);

        if (user == null)
            return NotFound(ApiResponse<object>.Error("Usuário não encontrado."));

        try
        {
            var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
            var result = await userManager.ConfirmEmailAsync(user, decodedToken);

            if (result.Succeeded)
                return Ok(ApiResponse<object>.Success(null, "E-mail confirmado com sucesso!"));

            return BadRequest(
                ApiResponse<object>.Error(
                    "Erro ao confirmar o e-mail. O token pode ser inválido ou já ter sido usado."));
        }
        catch (FormatException)
        {
            return BadRequest(ApiResponse<object>.Error("O formato do token é inválido."));
        }
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

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        var user = await userManager.FindByEmailAsync(request.Email);

        if (user == null || !await userManager.IsEmailConfirmedAsync(user))
            return Ok(ApiResponse<object>.Success(null, "Se uma conta com este e-mail existir, um link para redefinição de senha foi enviado."));
        
        var token = await userManager.GeneratePasswordResetTokenAsync(user);
        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
        var callbackUrl = $"{configuration["FrontendUrl:ResetPasswordUrl"]}?email={user.Email}&token={encodedToken}";
        await emailSender.SendPasswordResetLinkAsync(user, user.Email!, callbackUrl);

        return Ok(ApiResponse<object>.Success(null, "Se uma conta com este e-mail existir, um link para redefinição de senha foi enviado."));
    }
    
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        var user = await userManager.FindByEmailAsync(request.Email);
        
        if (user == null)
            return BadRequest(ApiResponse<object>.Error("Usuário não encontrado."));
        
        try
        {
            var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(request.Token));
            var result = await userManager.ResetPasswordAsync(user, decodedToken, request.NewPassword);

            if (result.Succeeded)
                return Ok(ApiResponse<object>.Success(null, "Senha redefinida com sucesso."));
        
            var errors = new Dictionary<string, List<string>>();
            foreach (var error in result.Errors)
            {
                if (!errors.ContainsKey(error.Code))
                {
                    errors[error.Code] = new List<string>();
                }
                errors[error.Code].Add(error.Description);
            }
            return BadRequest(ApiResponse<object>.Error("Erro ao redefinir a senha.", errors));
        }
        catch (FormatException)
        {
            return BadRequest(ApiResponse<object>.Error("O formato do token é inválido."));
        }
    }
    
    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] TokenRequest request)
    {
        var principal = GetPrincipalFromExpiredToken(request.AccessToken);
    
        var username = principal?.Identity?.Name;
        if (username is null)
            return BadRequest(ApiResponse<object>.Error("Access Token inválido ou malformado."));
    
        var user = await userManager.FindByNameAsync(username);

        if (user == null || user.RefreshToken != request.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            return BadRequest(ApiResponse<object>.Error("Refresh Token inválido ou expirado. Por favor, faça login novamente."));
        
        var newAccessToken = await GenerateJwtToken(user);
        var newRefreshToken = GenerateRefreshToken();
    
        user.RefreshToken = newRefreshToken;
        await userManager.UpdateAsync(user);
    
        var tokenResponse = new TokenResponse
        {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken
        };

        return Ok(ApiResponse<TokenResponse>.Success(tokenResponse));
    }
    
    private ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = true,
            ValidateIssuer = true,
            ValidAudience = configuration["JWT:ValidAudience"],
            ValidIssuer = configuration["JWT:ValidIssuer"],
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]!)),
            ValidateLifetime = false 
        };

        var tokenHandler = new JwtSecurityTokenHandler();
    
        try
        {
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
        
            if (securityToken is not JwtSecurityToken jwtSecurityToken || 
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                return null;

            return principal;
        }
        catch
        {
            return null;
        }
    }

    
    
}
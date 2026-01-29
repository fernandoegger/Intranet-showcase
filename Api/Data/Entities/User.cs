using Microsoft.AspNetCore.Identity;

namespace Api.Data.Entities;

public class User : IdentityUser
{
    public string? RefreshToken { get; set; }
    public DateTime RefreshTokenExpiryTime { get; set; }
    public required string Name { get; set; }
    public int Registration { get; set; }
    public Department Department { get; set; }
    public int DepartmentId { get; set; }
    public bool IsActive { get; set; }
}
using Microsoft.AspNetCore.Identity;

namespace Api.Data.Entities;

public class User : IdentityUser
{
    public string? RefreshToken { get; set; }
    public DateTime RefreshTokenExpiryTime { get; set; }
    public string Name { get; set; }
    public int Registration { get; set; }
    public Department Department { get; set; }
    public int DepartmentId { get; set; }
    public ICollection<RequestApprovment> RequestApprovments { get; set; }
    public ICollection<Request> Requests { get; set; }
    public bool IsActive { get; set; }
}
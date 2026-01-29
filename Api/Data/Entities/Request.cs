namespace Api.Data.Entities;

public class Request
{
    public int Id { get; set; }
    public Guid Uid { get; set; } = Guid.NewGuid();
    public int Number { get; set; }
    public User Claimant { get; set; }
    public int ClaimantId { get; set; }
    public Department Department { get; set; }
    public int DepartmentId { get; set; }
    public RequestStatus RequestStatus { get; set; }
    public int RequestStatusId { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public DateTime LastUpdatedAt { get; set; }
    public string Note{ get; set; }
    public decimal TotalValue { get; set; }
}
namespace Api.Data.Entities;

public class Request : EntityBase
{
    public int Number { get; set; }
    public User Claimant { get; set; }
    public string ClaimantId { get; set; }
    public Department Department { get; set; }
    public int DepartmentId { get; set; }
    public RequestStatus RequestStatus { get; set; }
    public int RequestStatusId { get; set; }
    public RequestApprovment? RequestApprovment { get; set; }
    public int? RequestApprovmentId { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public DateTime LastUpdatedAt { get; set; } = DateTime.Now;
    public string Note{ get; set; }
    public decimal TotalValue { get; set; }
    public ICollection<RequestItem> RequestItems { get; set; }
    public ICollection<RequestHistory> RequestHistories { get; set; }
}
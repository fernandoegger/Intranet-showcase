namespace Api.Data.Entities;

public class RequestApprovment
{
    public int Id { get; set; }
    public Guid Uid { get; set; } = Guid.NewGuid();
    public Request Request { get; set; }
    public int RequestId { get; set; }
    public User Approver { get; set; }
    public int ApproverId { get; set; }
    public int ApprovmentLevel { get; set; }
    public string Status { get; set; }
    public DateTime DateTime { get; set; }
    public string Note { get; set; }
}
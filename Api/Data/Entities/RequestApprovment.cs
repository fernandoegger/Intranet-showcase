namespace Api.Data.Entities;

public class RequestApprovment : EntityBase
{
    public Request Request { get; set; }
    public int RequestId { get; set; }
    public User Approver { get; set; }
    public string ApproverId { get; set; }
    public DateTime DateTime { get; set; } = DateTime.Now;
    public string Note { get; set; }
}
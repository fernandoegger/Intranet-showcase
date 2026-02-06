namespace Api.Data.Entities;

public class RequestHistory : EntityBase
{
    public Request Request { get; set; }
    public int RequestId { get; set; }
    public RequestStatus? PreviousStatus { get; set; }
    public int? PreviousStatusId { get; set; }
    public RequestStatus NewStatus { get; set; }
    public int NewStatusId { get; set; }
    public User UpdatedBy { get; set; }
    public string UpdatedById { get; set; }
    public DateTime UpdatedAt { get; set; } = DateTime.Now;
    public string? Note { get; set; }
}
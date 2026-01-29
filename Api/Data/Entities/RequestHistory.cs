namespace Api.Data.Entities;

public class RequestHistory
{
    public int Id { get; set; }
    public Guid Uid { get; set; } = Guid.NewGuid();
    public Request Request { get; set; }
    public int RequestId { get; set; }
    public RequestStatus PreviousStatus { get; set; }
    public int PreviousStatusId { get; set; }
    public RequestStatus NewStatus { get; set; }
    public int NewStatusId { get; set; }
    public User User { get; set; }
    public int UserId { get; set; }
    public DateTime Date { get; set; }
    public string Comment { get; set; }
}
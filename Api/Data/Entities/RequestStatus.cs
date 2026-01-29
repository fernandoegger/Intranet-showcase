namespace Api.Data.Entities;

public class RequestStatus
{
    public int Id { get; set; }
    public Guid Uid { get; set; } = Guid.NewGuid();
    public string Code { get; set; }
    public string Description { get; set; }
    public int Order { get; set; }
    public bool IsFinal { get; set; }
}
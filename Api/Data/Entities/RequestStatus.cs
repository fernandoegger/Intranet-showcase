namespace Api.Data.Entities;

public class RequestStatus : EntityBase
{
    public string Code { get; set; }
    public string Description { get; set; }
    public int Order { get; set; }
    public bool IsFinal { get; set; }
}
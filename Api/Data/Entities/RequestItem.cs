namespace Api.Data.Entities;

public class RequestItem : EntityBase
{
    public Request Request { get; set; }
    public int RequestId { get; set; }
    public string ProductName { get; set; }
    public string? Description { get; set; }
    public double Quantity { get; set; }
    public string Measurement { get; set; }
    public decimal UnitPrice { get; set; }
    public decimal TotalPrice { get; set; }
    public string? Note { get; set; }
}
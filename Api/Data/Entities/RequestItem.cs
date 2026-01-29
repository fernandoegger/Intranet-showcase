namespace Api.Data.Entities;

public class RequestItem
{
    public int Id { get; set; }
    public Guid Uid { get; set; } = Guid.NewGuid();
    public required Request Request { get; set; }
    public int RequestId { get; set; }
    public required string Product { get; set; }
    public string? Description { get; set; }
    public double Quantity { get; set; }
    public required string Measurement { get; set; }
    public decimal UnitPrice { get; set; }
    public decimal TotalPrice { get; set; }
    public string? Note { get; set; }
}
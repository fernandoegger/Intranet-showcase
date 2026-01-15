namespace Api.Data.Entities;

public class Request
{
    public int Id { get; set; }
    public Guid Uid { get; set; } = Guid.NewGuid();
    public int Number { get; set; }
    public string Description { get; set; } = null!;
    public DateTime Date { get; set; }
    public string? Observations { get; set; }
    public bool Active { get; set; }
    public List<Category>? Categories { get; set; }
}
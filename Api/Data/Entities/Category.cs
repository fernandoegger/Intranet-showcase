namespace Api.Data.Entities;

public class Category
{
    public int Id { get; set; }
    public Guid Uid { get; set; } = Guid.NewGuid();
    public string Description { get; set; } = null!;
    public List<Request> Requests { get; set; }
}
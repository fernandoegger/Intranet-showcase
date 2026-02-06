namespace Api.Data.Entities;

public abstract class EntityBase
{
    public int Id { get; set; }
    public Guid Uid { get; set; } = Guid.NewGuid();
}
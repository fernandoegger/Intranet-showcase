namespace Api.Data.Entities;

public class Department
{
    public int Id { get; set; }
    public Guid Uid { get; set; } = Guid.NewGuid();
    public string Name { get; set; }
    public User Manager { get; set; }
    public int ManagerId { get; set; }
}
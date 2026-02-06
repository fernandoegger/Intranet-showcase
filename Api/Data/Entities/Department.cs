namespace Api.Data.Entities;

public class Department: EntityBase
{
    public string Name { get; set; }
    public ICollection<User> Managers { get; set; }
    public ICollection<Request> Requests { get; set; }
}
using Api.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace Api.Data;

public class AppDbContext : DbContext
{
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        => optionsBuilder.UseSqlite("Data Source=app.db");

    public DbSet<Request> Requests { get; set; }
    public DbSet<Category> Categories { get; set; }
}
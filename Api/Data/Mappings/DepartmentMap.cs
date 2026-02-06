using Api.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Api.Data.Mappings;

public class DepartmentMap : IEntityTypeConfiguration<Department>
{
    public void Configure(EntityTypeBuilder<Department> builder)
    {
        builder.ToTable("Departments");
        builder.HasKey(d => d.Id);
        builder.Property(d => d.Id)
            .ValueGeneratedOnAdd();
        
        builder.Property(d => d.Uid)
            .HasColumnName("Uid")
            .HasMaxLength(100)
            .IsRequired();
        
        builder.Property(d => d.Name)
            .HasColumnName("Name")
            .HasMaxLength(100)
            .IsRequired();
        
        builder.HasMany(d => d.Managers)
            .WithOne(d => d.Department)
            .HasForeignKey(d => d.DepartmentId)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
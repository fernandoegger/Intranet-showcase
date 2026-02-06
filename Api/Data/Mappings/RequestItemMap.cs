using Api.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Api.Data.Mappings;

public class RequestItemMap : IEntityTypeConfiguration<RequestItem>
{
    public void Configure(EntityTypeBuilder<RequestItem> builder)
    {
        builder.ToTable("RequestItems");
        builder.HasKey(ri => ri.Id);
        builder.Property(ri => ri.Id)
            .ValueGeneratedOnAdd();
        
        builder.Property(ri => ri.Uid)
            .HasColumnName("Uid")
            .HasMaxLength(100)
            .IsRequired();
        
        builder.HasOne(ri => ri.Request)
            .WithMany(r => r.RequestItems)
            .HasForeignKey(ri => ri.RequestId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.Property(ri => ri.ProductName)
            .HasColumnName("ProductName")
            .HasMaxLength(100)
            .IsRequired();
        
        builder.Property(ri => ri.Description)
            .HasColumnName("Description")
            .HasMaxLength(500)
            .IsRequired(false);
        
        builder.Property(ri => ri.Quantity)
            .HasColumnName("Quantity")
            .IsRequired();
        
        builder.Property(ri => ri.Measurement)
            .HasColumnName("Measurement")
            .HasMaxLength(50)
            .IsRequired();

        builder.Property(ri => ri.UnitPrice)
            .HasColumnName("UnitPrice")
            .IsRequired();
        
        builder.Property(ri => ri.TotalPrice)
            .HasColumnName("TotalPrice")
            .IsRequired();
        
        builder.Property(ri => ri.Note)
            .HasColumnName("Note")
            .HasMaxLength(1000)
            .IsRequired(false);
    }
}
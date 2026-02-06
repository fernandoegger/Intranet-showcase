using Api.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Api.Data.Mappings;

public class RequestStatusMap : IEntityTypeConfiguration<RequestStatus>
{
    public void Configure(EntityTypeBuilder<RequestStatus> builder)
    {
        builder.ToTable("RequestStatus");
        builder.HasKey(rs => rs.Id);
        builder.Property(rs => rs.Id)
            .ValueGeneratedOnAdd();
        
        builder.Property(rs => rs.Uid)
            .HasColumnName("Uid")
            .HasMaxLength(100)
            .IsRequired();
        
        builder.Property(rs => rs.Code)
            .HasColumnName("Code")
            .HasMaxLength(20)
            .IsRequired();
        
        builder.Property(rs => rs.Description)
            .HasColumnName("Description")
            .HasMaxLength(500)
            .IsRequired();
        
        builder.Property(rs => rs.Order)
            .HasColumnName("Order")
            .IsRequired();
        
        builder.Property(rs => rs.IsFinal)
            .HasColumnName("IsFinal")
            .IsRequired();
    }
}
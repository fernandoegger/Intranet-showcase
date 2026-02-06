using Api.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Api.Data.Mappings;

public class RequestApprovmentMap : IEntityTypeConfiguration<RequestApprovment>
{
    public void Configure(EntityTypeBuilder<RequestApprovment> builder)
    {
        builder.ToTable("RequestApprovments");
        builder.HasKey(d => d.Id);
        builder.Property(d => d.Id)
            .ValueGeneratedOnAdd();
        
        builder.Property(d => d.Uid)
            .HasColumnName("Uid")
            .HasMaxLength(100)
            .IsRequired();

        builder.HasOne(ra => ra.Request)
            .WithOne(r => r.RequestApprovment)
            .HasForeignKey<RequestApprovment>(ra => ra.RequestId)
            .OnDelete(DeleteBehavior.Restrict)
            .IsRequired();

        builder.HasOne(ra => ra.Approver)
            .WithMany(u => u.RequestApprovments)
            .HasForeignKey(ra => ra.ApproverId)
            .OnDelete(DeleteBehavior.Restrict)
            .IsRequired();

        builder.Property(d => d.DateTime)
            .HasColumnName("DateTime")
            .IsRequired();

        builder.Property(d => d.Note)
            .HasColumnName("Note")
            .HasMaxLength(1000)
            .IsRequired(false);
    }
}
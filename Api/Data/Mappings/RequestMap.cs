using Api.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Api.Data.Mappings;

public class RequestMap : IEntityTypeConfiguration<Request>
{
    public void Configure(EntityTypeBuilder<Request> builder)
    {
        builder.ToTable("Requests");
        builder.HasKey(r => r.Id);
        builder.Property(r => r.Id)
            .ValueGeneratedOnAdd();
        
        builder.Property(r => r.Uid)
            .HasColumnName("Uid")
            .HasMaxLength(100)
            .IsRequired();

        builder.Property(r => r.Number)
            .HasColumnName("Number")
            .IsRequired();
        
        builder.HasOne(r => r.Claimant)
            .WithMany(u => u.Requests)
            .HasForeignKey(r => r.ClaimantId)
            .OnDelete(DeleteBehavior.Restrict);
        
        builder.HasOne(r => r.Department)
            .WithMany(d => d.Requests)
            .HasForeignKey(r => r.DepartmentId)
            .OnDelete(DeleteBehavior.Restrict)
            .IsRequired();
        
        builder.HasOne(r => r.RequestStatus)
            .WithMany()
            .HasForeignKey(r => r.RequestStatusId)
            .OnDelete(DeleteBehavior.Restrict)
            .IsRequired();
        
        builder.HasOne(r => r.RequestApprovment)
            .WithOne(ra => ra.Request)
            .OnDelete(DeleteBehavior.Restrict)
            .IsRequired(false);
        
        builder.Property(r => r.CreatedAt)
            .HasColumnName("CreatedAt")
            .IsRequired();
        
        builder.Property(r => r.LastUpdatedAt)
            .HasColumnName("LastUpdatedAt")
            .IsRequired();
        
        builder.Property(r => r.Note)
            .HasColumnName("Note")
            .HasMaxLength(1000)
            .IsRequired(false);
        
        builder.Property(r => r.TotalValue)
            .HasColumnName("TotalValue")
            .IsRequired();
            
    }
}
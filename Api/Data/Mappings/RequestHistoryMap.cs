using Api.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Api.Data.Mappings;

public class RequestHistoryMap : IEntityTypeConfiguration<RequestHistory>
{
    public void Configure(EntityTypeBuilder<RequestHistory> builder)
    {
        builder.ToTable("RequestHistories");
        builder.HasKey(rh => rh.Id);
        builder.Property(rh => rh.Id)
            .ValueGeneratedOnAdd();
        
        builder.Property(rh => rh.Uid)
            .HasColumnName("Uid")
            .HasMaxLength(100)
            .IsRequired();

        builder.HasOne(rh => rh.Request)
            .WithMany(r => r.RequestHistories)
            .HasForeignKey(rh => rh.RequestId)
            .IsRequired();

        builder.HasOne(rh => rh.PreviousStatus)
            .WithMany()
            .HasForeignKey(rh => rh.PreviousStatusId)
            .IsRequired(false);
        
        builder.HasOne(rh => rh.NewStatus)
            .WithMany()
            .HasForeignKey(rh => rh.NewStatusId)
            .IsRequired();
        
        builder.HasOne(rh => rh.UpdatedBy)
            .WithMany()
            .HasForeignKey(rh => rh.UpdatedById)
            .IsRequired();

        builder.Property(rh => rh.UpdatedAt)
            .HasColumnName("UpdatedAt")
            .IsRequired();

        builder.Property(rh => rh.Note)
            .HasColumnName("Note")
            .HasMaxLength(1000)
            .IsRequired(false);
    }
}
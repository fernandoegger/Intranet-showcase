using Api.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Api.Data.Mappings;

public class Usermap : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.Property(u => u.UserName)
            .HasColumnName("Username")
            .HasColumnType("nvarchar")
            .HasMaxLength(50)
            .IsRequired();

        builder.Property(u => u.NormalizedUserName)
            .HasColumnName("NormalizedUsername")
            .HasColumnType("nvarchar")
            .HasMaxLength(50);
        
        builder.Property(u => u.Email)
            .HasColumnName("Email")
            .HasColumnType("nvarchar")
            .HasMaxLength(100)
            .IsRequired();

        builder.Property(u => u.NormalizedEmail)
            .HasColumnName("NormalizedEmail")
            .HasColumnType("nvarchar")
            .HasMaxLength(100);

        builder.Property(u => u.Name)
            .HasColumnName("Name")
            .HasColumnType("nvarchar")
            .HasMaxLength(100)
            .IsRequired();

        builder.Property(u => u.RefreshToken)
            .HasColumnName("RefreshToken")
            .HasColumnType("nvarchar")
            .HasMaxLength(500)
            .IsRequired(false);

        builder.Property(u => u.RefreshTokenExpiryTime)
            .HasColumnName("RefreshTokenExpiryTime")
            .HasColumnType("datetime2")
            .IsRequired();
    }
}
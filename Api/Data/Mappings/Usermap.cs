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
            .HasMaxLength(50)
            .IsRequired();

        builder.Property(u => u.NormalizedUserName)
            .HasColumnName("NormalizedUsername")
            .HasMaxLength(50);
        
        builder.Property(u => u.Email)
            .HasColumnName("Email")
            .HasMaxLength(100)
            .IsRequired();

        builder.Property(u => u.NormalizedEmail)
            .HasColumnName("NormalizedEmail")
            .HasMaxLength(100);

        builder.Property(u => u.Name)
            .HasColumnName("Name")
            .HasMaxLength(100)
            .IsRequired();

        builder.Property(u => u.RefreshToken)
            .HasColumnName("RefreshToken")
            .HasMaxLength(500)
            .IsRequired(false);

        builder.Property(u => u.RefreshTokenExpiryTime)
            .HasColumnName("RefreshTokenExpiryTime")
            .IsRequired();
    }
}
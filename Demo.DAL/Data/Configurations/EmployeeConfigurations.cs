using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RouteG03.DAL.Models.EmployeeModules;

namespace RouteG03.DAL.Data.Configurations
{
    public class EmployeeConfigurations : BaseEntityConfigurations<Employee>, IEntityTypeConfiguration<Employee>
    {
        public void Configure(EntityTypeBuilder<Employee> builder)
        {
            builder.Property(e => e.Name).HasColumnType("varchar(50)");
            builder.Property(e => e.Address).HasColumnType("varchar(50)");
            builder.Property(e => e.Salary).HasColumnType("decimal(10,2)");
            builder.Property(e => e.Gender)
                .HasConversion(
                    e => e.ToString(),
                    e => Enum.Parse<Gender>(e)
                );
            builder.Property(e => e.EmployeeType)
                .HasConversion(
                    e => e.ToString(),
                    e => Enum.Parse<EmployeeType>(e)
                );
            base.Configure(builder);



        }
    }
}

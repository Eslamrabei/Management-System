

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RouteG03.DAL.Models.DepartmentModules;

namespace RouteG03.DAL.Data.Configurations
{
    public class DepartmentConfigurations : BaseEntityConfigurations<Department>, IEntityTypeConfiguration<Department>
    {
        public void Configure(EntityTypeBuilder<Department> builder)
        {
            builder.Property(D => D.Id).UseIdentityColumn(10, 10);
            builder.Property(D => D.Name).HasColumnType("varchar(20)");
            builder.Property(D => D.Code).HasColumnType("varchar(20)");
            builder.Property(D => D.Description).HasColumnType("varchar(20)");
            base.Configure(builder);


            //Relations
            builder.HasMany(Emps => Emps.Employees)
                .WithOne(Dept => Dept.Department)
                .HasForeignKey(key => key.DepartmentId)
                .OnDelete(DeleteBehavior.SetNull);


        }
    }
}

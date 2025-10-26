using RouteG03.DAL.Models.EmployeeModules;

namespace RouteG03.DAL.Models.DepartmentModules
{
    public class Department : BaseEntity
    {
        public string Name { get; set; } = null!;
        public string Code { get; set; } = null!;
        public string? Description { get; set; }

        //Navigation 
        public virtual ICollection<Employee> Employees { get; set; } = [];
    }
}

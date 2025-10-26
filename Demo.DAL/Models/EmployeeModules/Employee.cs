



using RouteG03.DAL.Models.DepartmentModules;

namespace RouteG03.DAL.Models.EmployeeModules
{
    public class Employee : BaseEntity
    {
        public string Name { get; set; } = null!;
        [Range(24, 50, ErrorMessage = "Please enter an age between 24 -50: ")]
        public int Age { get; set; }
        [RegularExpression(@"^\[\d+-[a-zA-Z\s]+-[a-zA-Z\s]+-[a-zA-Z\s]+\]$",
        ErrorMessage = "Address must be in the format [number-street-city-country]")]
        public string? Address { get; set; }
        public bool IsActive { get; set; }
        public decimal Salary { get; set; }
        public string? Email { get; set; }
        public Gender Gender { get; set; }
        public EmployeeType EmployeeType { get; set; }
        public string? PhoneNumber { get; set; }
        public DateTime HiringDate { get; set; }

        // FK
        public int? DepartmentId { get; set; }
        // Navigation
        public virtual Department? Department { get; set; }

        public string? ImageName { get; set; }
    }
}

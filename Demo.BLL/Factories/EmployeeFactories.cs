using RouteG03.DAL.Models.EmployeeModules;

namespace RouteG03.BLL.Factories
{
    public static class EmployeeFactories
    {

        public static Employee ToEntity(this CreateEmployeeDto createEmployee)
        {
            return new Employee()
            {
                Name = createEmployee.Name,
                Age = createEmployee.Age.HasValue ? createEmployee.Age.Value : default,
                Address = createEmployee.Address,
                IsActive = createEmployee.IsActive,
                Salary = createEmployee.Salary,
                Email = createEmployee.Email,
                Gender = createEmployee.Gender,
                EmployeeType = createEmployee.EmployeeType,
                PhoneNumber = createEmployee.PhoneNumber,
                HiringDate = createEmployee.HiringDate.ToDateTime(new TimeOnly()),
                CreatedBy = 1,
                LastModifiedBy = 1
            };
        }

        public static EmployeesDto RequestFromEmployee(this Employee employee)
        {
            return new EmployeesDto()
            {
                Id = employee.Id,
                Name = employee.Name,
                Age = employee.Age,
                IsActive = employee.IsActive,
                Email = employee.Email,
                EmployeeType = employee.EmployeeType.ToString(),
                Gender = employee.Gender.ToString(),
                Salary = employee.Salary
            };
        }

        public static EmployeeDetailsDto RequestFromEmployeeWithID(this Employee employee)
        {
            return new EmployeeDetailsDto()
            {
                Id = employee.Id,
                Name = employee.Name,
                Age = employee.Age,
                Address = employee.Address,
                IsActive = employee.IsActive,
                Salary = employee.Salary,
                Email = employee.Email,
                Gender = employee.Gender.ToString(),
                EmployeeType = employee.EmployeeType.ToString(),
                PhoneNumber = employee.PhoneNumber,
                HiringDate = DateOnly.FromDateTime(employee.HiringDate),
                CreatedBy = 1,
                LastModifiedBy = 1
            };
        }

        public static Employee UpdateToEntity(this UpdateEmployeeDto employeeDto)
        {
            return new Employee()
            {
                Name = employeeDto.Name,
                Age = employeeDto.Age.HasValue ? employeeDto.Age.Value : default,
                Address = employeeDto.Address,
                IsActive = employeeDto.IsActive,
                Salary = employeeDto.Salary,
                Email = employeeDto.Email,
                Gender = employeeDto.Gender,
                EmployeeType = employeeDto.EmployeeType,
                PhoneNumber = employeeDto.PhoneNumber,
                HiringDate = employeeDto.HiringDate.ToDateTime(new TimeOnly()),
                CreatedBy = 1,
                LastModifiedBy = 1
            };
        }
    }
}

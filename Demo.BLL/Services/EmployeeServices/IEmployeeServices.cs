using Microsoft.AspNetCore.Http;

namespace RouteG03.BLL.Services.EmployeeServices
{
    public interface IEmployeeServices
    {
        IEnumerable<EmployeesDto> GetAllEmployees(string? EmployeeSearchName, bool withTracking = false);
        EmployeeDetailsDto? GetEmployeeById(int id);
        int AddEmployee(CreateEmployeeDto createEmployeeDto);
        int UpdateEmployee(UpdateEmployeeDto updateEmployeeDto);
        bool DeleteEmployee(int id);
        public bool DeleteImage(int id);
        public bool UpdateEmployeeImage(int id, IFormFile photo);
    }
}

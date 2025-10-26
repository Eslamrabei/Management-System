using RouteG03.BLL.Dtos.DepartmentsDtos;

namespace RouteG03.BLL.Services.DepartmentServices
{
    public interface IDepartmentServices
    {
        IEnumerable<DepartmentsDto> GetAllDepartments(string? DepartmentSearchName = null, bool withTracking = false);
        DepartmentDetailsDto? GetDepartmentbyId(int id);
        int AddDepartment(CreateDepartmentDto departmentDto);
        int Update(UpdatedDepartmentDto departmentDto);
        bool Delete(int id);
    }
}

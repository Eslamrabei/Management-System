using Demo.DAL.Ropsitories.Shared;
using RouteG03.BLL.Dtos.DepartmentsDtos;
using RouteG03.DAL.Models.DepartmentModules;

namespace RouteG03.BLL.Services.DepartmentServices
{
    public class DepartmentServices(IUniteOfWork _UniteOfWork) : IDepartmentServices
    {
        public IEnumerable<DepartmentsDto> GetAllDepartments(string? DepartmentSearchName, bool withTracking = false)
        {
            IEnumerable<Department> departments;
            if (!string.IsNullOrWhiteSpace(DepartmentSearchName))
                departments = _UniteOfWork.DepartmentRepository.GetAll(Dept => Dept.Name.ToLower().Contains(DepartmentSearchName.ToLower()));
            else
                departments = _UniteOfWork.DepartmentRepository.GetAll(withTracking);
            return departments.Select(D => D.ReturnToDepartmentsDto());
        }

        public DepartmentDetailsDto? GetDepartmentbyId(int id)
        {
            var deparmtent = _UniteOfWork.DepartmentRepository.GetById(id);
            return deparmtent?.ReturnToDepartmentDetailsDto();
        }

        public int AddDepartment(CreateDepartmentDto departmentDto)
        {
            _UniteOfWork.DepartmentRepository.Add(departmentDto.ToEntity());
            return _UniteOfWork.SaveChanges();
        }
        public int Update(UpdatedDepartmentDto departmentDto)
        {
            _UniteOfWork.DepartmentRepository.Update(departmentDto.ToUpdateEntity());
            return _UniteOfWork.SaveChanges();
        }
        // Soft Delete.
        public bool Delete(int id)
        {
            var department = _UniteOfWork.DepartmentRepository.GetById(id);
            if (department == null) return false;
            else
            {
                department.IsDeleted = true;
                _UniteOfWork.DepartmentRepository.Update(department);
                return _UniteOfWork.SaveChanges() > 0;
            }
        }


    }
}
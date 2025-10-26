global using RouteG03.BLL.Dtos.EmployeesDtos;
global using RouteG03.BLL.Factories;
using AutoMapper;
using Demo.BLL.AttachmentsService;
using Demo.DAL.Ropsitories.Shared;
using Microsoft.AspNetCore.Http;
using RouteG03.DAL.Models.EmployeeModules;

namespace RouteG03.BLL.Services.EmployeeServices
{
    public class EmployeeServices(IUniteOfWork _UniteOfWork, IMapper _mapper, IAttachmentservice _attachmentService) : IEmployeeServices
    {
        #region Services With Manual Mapping
        //public int AddEmployee(CreateEmployeeDto createEmployeeDto)
        //{
        //    return _employeeRepository.Add(createEmployeeDto.ToEntity());
        //}

        //public IEnumerable<EmployeesDto> GetAllEmployees(bool withTracking)
        //{
        //    var getEmployee = _employeeRepository.GetAll();
        //    return getEmployee.Select(e => e.RequestFromEmployee());
        //}

        //public EmployeeDetailsDto? GetEmployeeById(int id)
        //{
        //    var getEmployeeById = _employeeRepository.GetById(id);
        //    return getEmployeeById?.RequestFromEmployeeWithID();
        //}

        //public int UpdateEmployee(UpdateEmployeeDto updateEmployeeDto)
        //{
        //    return _employeeRepository.Update(updateEmployeeDto.UpdateToEntity());
        //}

        //public bool DeleteEmployee(int id)
        //{
        //    var employee = _employeeRepository.GetById(id);
        //    if (employee == null) return false;
        //    else
        //    {
        //        int result = _employeeRepository.Delete(employee);
        //        return result > 0;
        //    }
        //} 
        #endregion
        #region Services With AutoMapper Package

        public IEnumerable<EmployeesDto> GetAllEmployees(string? EmployeeSearchName, bool withTracking)
        {
            IEnumerable<Employee> employees;
            if (!string.IsNullOrWhiteSpace(EmployeeSearchName))
                employees = _UniteOfWork.EmployeeRepository.GetAll(Emp => Emp.Name.ToLower().Contains(EmployeeSearchName.ToLower()));
            else
                employees = _UniteOfWork.EmployeeRepository.GetAll(withTracking);
            return _mapper.Map<IEnumerable<Employee>, IEnumerable<EmployeesDto>>(employees);
        }

        public EmployeeDetailsDto? GetEmployeeById(int id)
        {
            var employee = _UniteOfWork.EmployeeRepository.GetById(id);
            return employee is null ? null : _mapper.Map<Employee, EmployeeDetailsDto>(employee);
        }
        public int AddEmployee(CreateEmployeeDto createEmployeeDto)
        {
            var CreateEmployee = _mapper.Map<CreateEmployeeDto, Employee>(createEmployeeDto);
            if (createEmployeeDto.Image != null)
            {
                CreateEmployee.ImageName = _attachmentService.Upload(createEmployeeDto.Image, "Images");
            }
            _UniteOfWork.EmployeeRepository.Add(CreateEmployee);
            return _UniteOfWork.SaveChanges();
        }
        public int UpdateEmployee(UpdateEmployeeDto updateEmployeeDto)
        {
            var UpdateEmployee = _mapper.Map<UpdateEmployeeDto, Employee>(updateEmployeeDto);

            _UniteOfWork.EmployeeRepository.Update(UpdateEmployee);
            return _UniteOfWork.SaveChanges();

        }

        // Soft Delete
        public bool DeleteEmployee(int id)
        {
            var GetEmployee = _UniteOfWork.EmployeeRepository.GetById(id);
            if (GetEmployee == null) return false;
            else
            {

                GetEmployee.IsDeleted = true;
                var filePath = Path.Combine(Directory.GetCurrentDirectory(), $"wwwroot\\Files\\Images", GetEmployee.ImageName != null ? GetEmployee.ImageName : "user.png");
                _attachmentService.Delete(filePath);
                _UniteOfWork.EmployeeRepository.Update(GetEmployee);
                return _UniteOfWork.SaveChanges() > 0;
            }
        }
        public bool DeleteImage(int id)
        {
            var employee = _UniteOfWork.EmployeeRepository.GetById(id);
            if (employee == null) return false;

            if (string.IsNullOrWhiteSpace(employee.ImageName) || employee.ImageName.Equals("user.jpg", StringComparison.OrdinalIgnoreCase))
                return false;

            var filePath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "Files", "Images", employee.ImageName);
            if (File.Exists(filePath))
            {
                _attachmentService.Delete(filePath);
            }

            employee.ImageName = "user.jpg";
            _UniteOfWork.EmployeeRepository.Update(employee);

            return _UniteOfWork.SaveChanges() > 0;
        }


        // Update Image
        public bool UpdateEmployeeImage(int id, IFormFile photo)
        {
            var employee = _UniteOfWork.EmployeeRepository.GetById(id);
            if (employee == null) return false;

            if (photo != null && photo.Length > 0)
            {
                if (!string.IsNullOrEmpty(employee.ImageName) && employee.ImageName != "user.jpg")
                {
                    var oldPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "Files", "Images", employee.ImageName);
                    if (File.Exists(oldPath))
                        File.Delete(oldPath);
                }
                var newFile = $"{Guid.NewGuid()}_{photo.FileName}";
                var newPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "Files", "Images", newFile);
                using FileStream Fs = new(newPath, FileMode.Create);
                photo.CopyTo(Fs);

                employee.ImageName = newFile;
                _UniteOfWork.EmployeeRepository.Update(employee);
                return _UniteOfWork.SaveChanges() > 0;
            }
            return false;
        }

        #endregion
    }
}
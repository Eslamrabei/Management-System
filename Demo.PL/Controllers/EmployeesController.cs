
using Demo.PL.Models.EmployeeModule;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RouteG03.BLL.Dtos.EmployeesDtos;
using RouteG03.BLL.Services.EmployeeServices;
using RouteG03.DAL.Models.Shared;

namespace Demo.PL.Controllers
{
    public class EmployeesController(IEmployeeServices _employeeServices,
        IWebHostEnvironment _env, ILogger<EmployeesController> _logger) : Controller
    {

        #region Index   
        [HttpGet]
        public IActionResult Index(string? Search)
        {
            var employees = _employeeServices.GetAllEmployees(Search);
            return View(employees);
        }
        public IActionResult Search(string? EmployeeSearchName)
        {
            var employees = _employeeServices.GetAllEmployees(EmployeeSearchName);
            return PartialView("PartialViews/_EmployeeSearchPartialView", employees);
        }
        #endregion

        #region Create
        [Authorize(Roles = "Admin,HR")]
        [HttpGet]
        public IActionResult Create()
        {
            return View();
        }
        [Authorize(Roles = "Admin,HR")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult SaveData(CreateEmployeeDto employeeDto)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    if (employeeDto == null) return NotFound();

                    int result = _employeeServices.AddEmployee(employeeDto);

                    if (result > 0)
                    {
                        TempData["Success"] = "Employee Created Successfully!";
                        return RedirectToAction("Index");
                    }
                    else
                    {
                        TempData["Error"] = "Employee could not be created!";
                        ModelState.AddModelError("", "Can not create Employee!");
                    }
                }
                catch (Exception ex)
                {
                    if (_env.IsDevelopment())
                    {
                        ModelState.AddModelError("", $"Can not add an Employee : {ex.Message}");
                    }
                    else
                    {
                        _logger.LogError($"Employee creation failed: {ex}");
                        return View("ErrorView", ex);
                    }
                }
            }
            else
            {
                TempData["Error"] = "Please fix the errors before submitting.";
            }

            return View("Create", employeeDto);
        }

        #endregion


        #region Details
        [HttpGet]
        public IActionResult Details(int id)
        {
            var employee = _employeeServices.GetEmployeeById(id);
            if (employee == null) return NotFound();
            return View(employee);
        }
        #endregion

        #region Edit 
        [HttpGet]
        public IActionResult Edit(int? id)
        {
            if (!id.HasValue) return BadRequest();
            var employee = _employeeServices.GetEmployeeById(id.Value);
            if (employee == null) return NotFound();
            var employeeVm = new EmployeeViewModel()
            {
                Id = employee.Id,
                Name = employee.Name,
                Address = employee.Address,
                Age = employee.Age,
                IsActive = employee.IsActive,
                HiringDate = employee.HiringDate,
                Salary = employee.Salary,
                EmployeeType = Enum.Parse<EmployeeType>(employee.EmployeeType),
                Gender = Enum.Parse<Gender>(employee.Gender),
                PhoneNumber = employee.PhoneNumber,
                Email = employee.Email,
                Image = employee.ImageName
            };
            return View(employeeVm);
        }

        [HttpPost]
        public IActionResult Edit([FromRoute] int? id, EmployeeViewModel employee)
        {
            try
            {
                if (!id.HasValue) return BadRequest();
                var updateEmployee = new UpdateEmployeeDto()
                {
                    Id = id.Value,
                    Name = employee.Name,
                    Address = employee.Address,
                    Age = employee.Age,
                    IsActive = employee.IsActive,
                    HiringDate = employee.HiringDate,
                    Salary = employee.Salary,
                    EmployeeType = employee.EmployeeType,
                    Gender = employee.Gender,
                    PhoneNumber = employee.PhoneNumber,
                    Email = employee.Email,


                };
                int result = _employeeServices.UpdateEmployee(updateEmployee);
                if (result > 0) return RedirectToAction("index");

            }
            catch (Exception ex)
            {
                if (_env.IsDevelopment())
                {
                    ModelState.AddModelError("", $"Can not add an Employee :{ex.Message}");
                }
                else
                {
                    _logger.LogError("ErrorHandel");
                }
            }

            return View(employee);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]

        public IActionResult UpdateImg(int id, IFormFile? photo)
        {
            if (photo == null) return BadRequest("No Photo exist");

            var result = _employeeServices.UpdateEmployeeImage(id, photo);
            if (!result) return NotFound();

            return RedirectToAction("Edit", new { id });
        }

        #endregion

        #region Delete 
        [Authorize(Roles = "Admin,HR")]
        [HttpPost]
        public IActionResult Delete(int? id)
        {
            if (!id.HasValue) return BadRequest();
            try
            {
                var getEmployee = _employeeServices.GetEmployeeById(id.Value);
                if (getEmployee == null) return NotFound();

                bool isDeleted = _employeeServices.DeleteEmployee(id.Value);
                if (isDeleted)
                    return RedirectToAction("Index");
            }
            catch (Exception ex)
            {
                if (_env.IsDevelopment())
                {
                    ModelState.AddModelError("", $"Can not add an Employee :{ex.Message}");
                }
                else
                {
                    _logger.LogError("ErrorHandel");
                }
            }
            return View("Index");
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]

        [ValidateAntiForgeryToken]
        public IActionResult DeleteImg(int id)
        {
            if (id <= 0) return BadRequest("Invalid id");

            var employee = _employeeServices.GetEmployeeById(id);
            if (employee == null) return NotFound();

            bool isDeleted = _employeeServices.DeleteImage(id);
            if (isDeleted)
                return RedirectToAction("Edit", new { id });

            TempData["Error"] = "Could not delete image";
            return RedirectToAction("Edit", new { id });
        }

        #endregion

    }
}


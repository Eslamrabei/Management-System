using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RouteG03.BLL.Dtos.DepartmentsDtos;
using RouteG03.BLL.Services.DepartmentServices;
using RouteG03.PL.Models.DepartmentsModules;

namespace RouteG03.PL.Controllers
{

    [Authorize(Roles = "HR,Admin")]

    public class DepartmentsController(IDepartmentServices _departmentServices, IWebHostEnvironment _env,
        ILogger<DepartmentsController> _logger) : Controller
    {
        #region Index 
        public IActionResult Index(string? DepartmentSearchName)
        {
            var departments = _departmentServices.GetAllDepartments(DepartmentSearchName);
            return View(departments);
        }
        public IActionResult Search(string? DepartmentSearchName)
        {
            var departments = _departmentServices.GetAllDepartments(DepartmentSearchName);
            return PartialView("PartialViews/_DepartmentSearchPartialView", departments);
        }
        #endregion

        #region Create 
        [Authorize(Roles = "Admin")]
        [HttpGet]
        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]

        public IActionResult SaveData(CreateDepartmentDto create)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    int result = _departmentServices.AddDepartment(create);

                    if (result > 0)
                    {
                        TempData["Success"] = "Department created successfully!";
                        return RedirectToAction("Index");
                    }
                    else
                    {
                        TempData["Error"] = "Department could not be created!";
                        ModelState.AddModelError("", "Department could not be created.");
                    }
                }
                catch (Exception ex)
                {
                    if (_env.IsDevelopment())
                    {
                        _logger.LogError($"Department could not be created : {ex.Message}");
                    }
                    else
                    {
                        _logger.LogError($"Department could not be created : {ex}");
                        return View("ErrorView", ex);
                    }
                }
            }
            else
            {
                TempData["Error"] = "Please fix the validation errors before submitting.";
            }

            return View("Create", create);
        }
        #endregion

        #region Details 
        public IActionResult Details(int? id)
        {
            if (!id.HasValue) return BadRequest();
            var department = _departmentServices.GetDepartmentbyId(id.Value);
            if (department == null) return NotFound();
            return View(department);
        }
        #endregion

        #region Edit
        [HttpGet]
        public IActionResult Edit(int? id)
        {
            if (!id.HasValue) return BadRequest();
            var department = _departmentServices.GetDepartmentbyId(id.Value);
            if (department == null) return NotFound();

            var DepartmentVm = new DepartmentViewModel()
            {
                Code = department.Code,
                Name = department.Name,
                Description = department.Description,
                DateOfCreation = department.CreatedOn
            };
            return View(DepartmentVm);
        }

        [HttpPost]
        public IActionResult Edit([FromRoute] int? id, DepartmentViewModel departmentViewModel)
        {
            try
            {
                if (!id.HasValue) return BadRequest();

                var UpdateDepartmentDto = new UpdatedDepartmentDto()
                {
                    Id = id.Value,
                    Code = departmentViewModel.Code,
                    Name = departmentViewModel.Name,
                    Description = departmentViewModel.Description,
                    DateOfCreation = departmentViewModel.DateOfCreation
                };

                int result = _departmentServices.Update(UpdateDepartmentDto);

                if (result > 0)
                {
                    TempData["Success"] = "Department updated successfully!";
                    return RedirectToAction("Index");
                }
                else
                {
                    TempData["Error"] = "Department could not be updated!";
                    ModelState.AddModelError("", "Department could not be updated.");
                }
            }
            catch (Exception ex)
            {
                if (_env.IsDevelopment())
                {
                    _logger.LogError($"Department could not be updated : {ex.Message}");
                }
                else
                {
                    _logger.LogError($"Department could not be updated : {ex}");
                    return View("ErrorView", ex);
                }
            }
            return View("Edit", departmentViewModel);
        }
        #endregion

        #region Delete
        [HttpPost]
        public IActionResult Delete(int id)
        {
            if (id == 0) return BadRequest();

            try
            {
                bool isDeleted = _departmentServices.Delete(id);
                if (isDeleted)
                {
                    TempData["Success"] = "Department deleted successfully!";
                    return RedirectToAction("Index");
                }
                else
                {
                    TempData["Error"] = "Department could not be deleted!";
                    ModelState.AddModelError("", "Department could not be deleted!");
                }
            }
            catch (Exception ex)
            {
                if (_env.IsDevelopment())
                {
                    _logger.LogError($"Department could not be deleted : {ex.Message}");
                }
                else
                {
                    _logger.LogError($"Department could not be deleted : {ex}");
                    return View("ErrorView", ex);
                }
            }

            return RedirectToAction(nameof(Index));
        }
        #endregion
    }
}

using Demo.DAL.Models.IdentityModule;
using Demo.PL.Models.RoleModule;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;

namespace Demo.PL.Controllers
{
    public class RoleController(RoleManager<IdentityRole> _roleManager, UserManager<ApplicationUser> _userManager, IWebHostEnvironment _env) : Controller
    {
        #region Index 
        [HttpGet]
        public IActionResult Index(string SearchValue)
        {
            var role = _roleManager.Roles.AsQueryable();
            if (!string.IsNullOrEmpty(SearchValue))
                role = role.Where(r => r.Name.ToLower().Contains(SearchValue.ToLower()));

            var roles = role.Select(r => new RoleViewModel()
            {
                Id = r.Id,
                Name = r.Name
            }).ToList();
            return View(roles);
        }
        #endregion

        #region AssignToUser
        [HttpGet]
        public async Task<IActionResult> AssignToUser(string roleId)
        {
            var role = await _roleManager.FindByIdAsync(roleId);
            if (role == null)
            {
                TempData["Error"] = "Role not found!";
                return RedirectToAction("Index");
            }

            var users = await _userManager.Users.ToListAsync();
            var model = new AssignRoleToUserViewModel()
            {
                RoleId = role.Id,
                RoleName = role.Name,
                Users = users.Select(u => new SelectListItem
                {
                    Value = u.Id,
                    Text = $"{u.UserName} ({u.Email})"
                }).ToList()
            };

            return View(model);
        }
        [HttpPost]
        public async Task<IActionResult> AssignToUser(AssignRoleToUserViewModel model)
        {
            if (ModelState.IsValid)
            {
                var role = await _roleManager.FindByIdAsync(model.RoleId);
                var user = await _userManager.FindByIdAsync(model.SelectedUserId);

                if (role == null || user == null)
                {
                    TempData["Error"] = "Role or User not found";
                    return RedirectToAction("Index");
                }


                var userRoles = await _userManager.GetRolesAsync(user);
                if (userRoles.Contains(role.Name))
                {
                    TempData["Error"] = $"User '{user.UserName}' already has the role '{role.Name}'!";
                    return RedirectToAction("AssignToUser", new { roleId = model.RoleId });
                }


                var result = await _userManager.AddToRoleAsync(user, role.Name);

                if (result.Succeeded)
                {
                    TempData["Success"] = $"Role '{role.Name}' assigned to user '{user.UserName}' successfully!";
                    return RedirectToAction("Index");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }

            var users = await _userManager.Users.ToListAsync();
            model.Users = users.Select(u => new SelectListItem
            {
                Value = u.Id,
                Text = $"{u.UserName} ({u.Email})"
            }).ToList();

            return View(model);
        }

        #endregion

        #region Create 
        [HttpGet]
        public IActionResult Create()
        {
            return View();
        }
        [HttpPost]
        public IActionResult Create(RoleViewModel roleViewModel)
        {
            if (!ModelState.IsValid) return BadRequest();
            string msg = "";
            try
            {
                var role = new IdentityRole()
                {
                    Id = roleViewModel.Id,
                    Name = roleViewModel.Name
                };
                var result = _roleManager.CreateAsync(role).Result;
                if (result.Succeeded)
                    return RedirectToAction("Index");
                else
                    msg = "Faild in  creating a role.";

            }
            catch (Exception ex)
            {

                msg = _env.IsDevelopment() ? ex.Message : "Sorry, Try again later!";
            }
            ModelState.AddModelError("", msg);
            return View(roleViewModel);
        }
        #endregion

        #region Details 
        [HttpGet]
        public IActionResult Details(string id)
        {
            var role = _roleManager.FindByIdAsync(id).Result;
            if (role == null) return NotFound();
            return View(new RoleViewModel()
            {
                Id = role.Id,
                Name = role.Name
            });
        }
        #endregion

        #region Edit
        [HttpGet]
        public IActionResult Edit(string id)
        {
            var role = _roleManager.FindByIdAsync(id).Result;
            if (role == null) return NotFound();
            return View(new RoleViewModel()
            {
                Name = role.Name
            });
        }
        [HttpPost]
        public IActionResult Edit(string id, RoleViewModel roleViewModel)
        {
            var role = _roleManager.FindByIdAsync(id).Result;
            if (role == null || role.Id != id) return NotFound();
            string msg = "";
            try
            {

                role.Name = roleViewModel.Name;
                var result = _roleManager.UpdateAsync(role).Result;
                if (result.Succeeded)
                    return RedirectToAction("Index");
                else
                    msg = "Can not update the role";
            }
            catch (Exception ex)
            {
                msg = _env.IsDevelopment() ? ex.Message : "Sorry, Try again later.";
            }
            ModelState.AddModelError("", msg);
            return View(roleViewModel);
        }
        #endregion

        #region Delete
        [HttpPost]
        public IActionResult Delete(string id)
        {
            var role = _roleManager.FindByIdAsync(id).Result;
            if (role == null) return NotFound();
            string msg = "";
            try
            {
                var result = _roleManager.DeleteAsync(role).Result;
                if (result.Succeeded)
                {
                    TempData["Success"] = "The Role deleted succesfully!";
                    return RedirectToAction("Index");
                }
                else
                    TempData["Error"] = "Error In Delete The Role";
            }
            catch (Exception ex)
            {

                msg = _env.IsDevelopment() ? ex.Message : "Sorry, try again later.";
            }
            ModelState.AddModelError("", msg);
            return View();
        }
        #endregion

    }
}

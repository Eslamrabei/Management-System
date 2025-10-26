using Demo.DAL.Models.IdentityModule;
using Demo.PL.Models.UserModule;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Demo.PL.Controllers
{
    public class UserController(UserManager<ApplicationUser> _userManager, IWebHostEnvironment _env
        ) : Controller
    {

        #region Index
        [HttpGet]
        public async Task<IActionResult> Index(string Searchvalue)
        {
            // Services -> Get All Users [UserManager]
            var usersQuery = _userManager.Users.AsQueryable();
            if (!string.IsNullOrEmpty(Searchvalue))
                usersQuery = usersQuery.Where(u => u.Email.ToLower().Contains(Searchvalue.ToLower()));



            var users = usersQuery.Select(u => new UserViewModel()
            {
                Id = u.Id,
                FirstName = u.FirstName,
                LastName = u.LastName,
                Email = u.Email,
                PhoneNumber = u.PhoneNumber,
                // Roles


            }).ToList();
            foreach (var user in users)
            {
                user.Roles = await _userManager.GetRolesAsync(await _userManager.FindByIdAsync(user.Id));
            }

            return View(users);
        }

        #endregion

        #region Details
        [HttpGet]
        public IActionResult Details(string? id)
        {
            if (id == null) return BadRequest();
            var user = _userManager.FindByIdAsync(id).Result;
            if (user == null) return NotFound();
            return View(new UserViewModel()
            {
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email,
                Roles = _userManager.GetRolesAsync(user).Result
            });
        }


        #endregion

        #region Edit 
        [HttpGet]
        public IActionResult Edit(string? id)
        {
            if (id == null) return BadRequest();
            var user = _userManager.FindByIdAsync(id).Result;
            if (user == null) return NotFound();
            return View(new UserViewModel()
            {
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email,
                Roles = _userManager.GetRolesAsync(user).Result
            });
        }

        [HttpPost]
        public IActionResult Edit(UserViewModel userViewModel, string id)
        {
            if (!ModelState.IsValid) return View(userViewModel);
            if (userViewModel.Id != id) return BadRequest();
            string msg = "";
            try
            {
                var user = _userManager.FindByIdAsync(id).Result;
                if (user == null) return NotFound();
                user.FirstName = userViewModel.FirstName;
                user.LastName = userViewModel.LastName;
                user.Email = userViewModel.Email;
                var result = _userManager.UpdateAsync(user).Result;
                if (result.Succeeded)
                    return RedirectToAction("Index");
                else
                    msg = "User can not update !";
            }
            catch (Exception ex)
            {
                msg = _env.IsDevelopment() ? ex.Message : "Can not update user , there are a problem";
            }
            ModelState.AddModelError("", msg);
            return View(userViewModel);
        }
        #endregion

        #region Delete
        [HttpPost]
        public IActionResult Delete(string id)
        {
            var user = _userManager.FindByIdAsync(id).Result;
            if (user == null) return BadRequest();
            string msg = "";
            try
            {
                var result = _userManager.DeleteAsync(user).Result;
                if (result.Succeeded)
                    return RedirectToAction("Index");
                else
                    msg = "Can not delete user";
            }
            catch (Exception ex)
            {
                msg = _env.IsDevelopment() ? ex.Message : "Faild in deleting user , please try again in another time.";
            }
            ModelState.AddModelError("", msg);
            return RedirectToAction("Index");
        }
        #endregion

    }
}

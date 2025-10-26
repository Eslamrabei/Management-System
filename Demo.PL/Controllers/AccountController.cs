using Demo.BLL.EmailSettings;
using Demo.DAL.Models.IdentityModule;
using Demo.PL.Models.IdentityModule;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Demo.PL.Controllers
{
    public class AccountController(UserManager<ApplicationUser> _userManager,
        SignInManager<ApplicationUser> _signinManager, IEmailSetting _emailSetting) : Controller
    {
        #region Register 
        [HttpGet]
        public IActionResult Register() => View();
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel registerViewModel)
        {
            if (!ModelState.IsValid) return View(registerViewModel);

            var userRegister = new ApplicationUser()
            {
                UserName = registerViewModel.UserName,
                Email = registerViewModel.Email,
                FirstName = registerViewModel.FirstName,
                LastName = registerViewModel.LastName,
                PhoneNumber = registerViewModel.PhoneNumber
            };

            var result = await _userManager.CreateAsync(userRegister, registerViewModel.Password);
            if (result.Succeeded)
                return RedirectToAction("Login");

            else
            {
                foreach (var Error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, Error.Description);
                }
            }
            return View(registerViewModel);
        }

        #endregion
        #region LogIn
        [HttpGet]
        public IActionResult LogIn() => View();
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LogIn(LogInViewModel logInViewModel)
        {
            if (!ModelState.IsValid) return BadRequest();

            var user = await _userManager.FindByEmailAsync(logInViewModel.Email);
            if (user is { })
            {
                var checkPassword = await _userManager.CheckPasswordAsync(user, logInViewModel.Password);
                if (checkPassword)
                {
                    var Result = await _signinManager
                        .PasswordSignInAsync(user, logInViewModel.Password, logInViewModel.RememberMe, false);
                    if (Result.IsNotAllowed)
                        ModelState.AddModelError("", "Your Account is not confirmed yet.");
                    if (Result.IsLockedOut)
                        ModelState.AddModelError("", "Your Account is Locked.");
                    if (Result.Succeeded)
                    {

                        return RedirectToAction(nameof(HomeController.Index), "Home");
                    }

                }
                TempData["Error"] = "Failed, try again!";

                ModelState.AddModelError("", "Login Faild!");
            }
            return View(logInViewModel);
        }


        #endregion
        #region Logout
        [HttpPost]

        public async Task<IActionResult> Logout(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            await _signinManager.SignOutAsync();

            return RedirectToAction(nameof(LogIn));
        }
        #endregion
        #region ForgetPassword
        [HttpGet]

        public IActionResult ForgetPassword()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> ForgetPassword(ForgetPasswordViewModel _forgetPasswordViewModel)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(_forgetPasswordViewModel.Email);
                if (user != null)
                {

                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                    var PasswordLink = Url.Action("ResetPassword", "Account",
                        new { email = _forgetPasswordViewModel.Email, token = token }, Request.Scheme);
                    var email = new Email()
                    {
                        To = _forgetPasswordViewModel.Email,
                        Subject = "Reset Your Password",
                        Body = PasswordLink
                    };
                    _emailSetting.SendEmail(email);
                    return View("ForgetPasswordConfirmMessage");
                }
            }
            ModelState.AddModelError("", "Fiald to resest password");
            return View(_forgetPasswordViewModel);
        }
        #endregion
        #region Reset Password
        [HttpGet]

        public IActionResult ResetPassword(string email, string token)
        {
            if (email == null || token == null)
                return NotFound();
            return View();
        }

        [HttpPost]

        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel reset)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(reset.Email);
                if (user != null)
                {
                    var result = await _userManager.ResetPasswordAsync(user, reset.Token, reset.Password);
                    if (result.Succeeded)
                        return View("ResetPasswordConfirmation");
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                    return View(reset);
                }
            }
            return View(reset);
        }
        #endregion


        #region External Login [Google - Facebook]       

        #region Google
        [HttpGet]
        public IActionResult GoogleLogin()
        {
            var redirectUrl = Url.Action("GoogleResponse");
            var properties = _signinManager.ConfigureExternalAuthenticationProperties(GoogleDefaults.AuthenticationScheme, redirectUrl);
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }
        [HttpGet]
        public async Task<IActionResult> GoogleResponse()
        {
            // Get info from Google
            var info = await _signinManager.GetExternalLoginInfoAsync();
            if (info == null)
                return RedirectToAction("LogIn");

            // Try to sign in directly (if user already linked)
            var result = await _signinManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
            if (result.Succeeded)
                return RedirectToAction("Index", "Home");

            // Get user email from Google
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (email == null)
                return RedirectToAction("LogIn");

            // Check if user already exists
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                user = new ApplicationUser
                {
                    UserName = email,
                    Email = email,
                    EmailConfirmed = true,
                    FirstName = info.Principal.FindFirstValue(ClaimTypes.GivenName),
                    LastName = info.Principal.FindFirstValue(ClaimTypes.Surname)
                };

                // Create user in Identity tables
                var createResult = await _userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                {
                    foreach (var error in createResult.Errors)
                        ModelState.AddModelError("", error.Description);
                    return View("Login");
                }

                // Add default Role if needed (like HR or User)
                var defaultRole = "User";
                if (!await _userManager.IsInRoleAsync(user, defaultRole))
                    await _userManager.AddToRoleAsync(user, defaultRole);

                // Link external login info to user
                await _userManager.AddLoginAsync(user, info);
            }

            // Sign in the user
            await _signinManager.SignInAsync(user, isPersistent: false);
            return RedirectToAction("Index", "Home");
        }
        #endregion
        #region FaceBook
        [HttpGet]
        public IActionResult FacebookLogin()
        {
            var returnUrl = Url.Action("FacebookRespone");
            var properties = _signinManager.ConfigureExternalAuthenticationProperties(FacebookDefaults.AuthenticationScheme, returnUrl);
            return Challenge(properties, FacebookDefaults.AuthenticationScheme);
        }
        [HttpGet]
        public async Task<IActionResult> FacebookRespone()
        {
            var info = await _signinManager.GetExternalLoginInfoAsync();
            if (info == null) return RedirectToAction("LogIn");

            var result = await _signinManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, false);
            if (result == null) return RedirectToAction("LogIn");

            var FacebookAccount = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (FacebookAccount == null) return RedirectToAction("LogIn");

            var user = await _userManager.FindByEmailAsync(FacebookAccount);
            if (user == null)
            {
                user = new ApplicationUser()
                {
                    UserName = FacebookAccount,
                    Email = FacebookAccount,
                    EmailConfirmed = true,
                    FirstName = info.Principal.FindFirstValue(ClaimTypes.GivenName) ?? "No",
                    LastName = info.Principal.FindFirstValue(ClaimTypes.Surname) ?? "Name"
                };

                var createUSer = await _userManager.CreateAsync(user);
                if (!createUSer.Succeeded)
                {
                    foreach (var error in createUSer.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                    return RedirectToAction(nameof(LogIn));
                }
                var defaultRole = "User";
                if (!await _userManager.IsInRoleAsync(user, defaultRole))
                    await _userManager.AddToRoleAsync(user, defaultRole);

                await _userManager.AddLoginAsync(user, info);
            }
            await _signinManager.SignInAsync(user, false);
            return RedirectToAction("Index", "Home");

        }

        #endregion


        #endregion


    }
}


using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentitySample.Repositories;
using IdentitySample.ViewModel.Account;
using Microsoft.AspNetCore.Identity;

namespace IdentitySample.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IMessageSender _messageSender;
        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IMessageSender messageSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _messageSender = messageSender;
        }

        [HttpGet]
        public IActionResult Register()
        {
            if (_signInManager.IsSignedIn(User))
            {
                return RedirectToAction("Index", "Home");
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new IdentityUser()
                {
                    UserName = model.UserName,
                    Email = model.Email,
                    EmailConfirmed = true
                };
                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    var emailConfirmationToken =
                        await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var emailMessage =
                        Url.Action("ConfirmEmail", "Account",
                            new {username = user.UserName, token = emailConfirmationToken},
                            Request.Scheme);
                    await _messageSender.SendEmailAsync(model.Email, "تایید ایمیل", emailMessage);
                    
                    return RedirectToAction("Index", "Home");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }
            return View(model);
        }
        
        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string userName, string token)
        {
            if (string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(token))
                return NotFound();
            
            var user = await _userManager.FindByNameAsync(userName);
            if (user == null) 
                return NotFound();
            
            var result = await _userManager.ConfirmEmailAsync(user, token);

            return Content(result.Succeeded ? "ایمیل با موفقیت تایید شد" : "ایمیل تایید نشد");
        }

        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            if (_signInManager.IsSignedIn(User))
                return RedirectToAction("Index", "Home");

            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model,string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(
                     model.UserName, model.Password, model.RememberMe, true);

                ViewData["ReturnUrl"] = returnUrl;

                if (result.Succeeded)
                {
                    if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                        return Redirect(returnUrl);
                        
                    return RedirectToAction("Index", "Home");
                }
                    

                if (result.IsLockedOut)
                {
                    ViewData["ErrorMessage"] = "اکانت شما به مدت 10 دقیقه غیر فعال شده است";
                    return View(model);
                }

                ModelState.AddModelError("", "نام کاربری و رمز عبور صحیح نیست");
            }
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LogOut()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
       
        public async Task<IActionResult> IsEmailInUse(string email)
        {
          var user = await  _userManager.FindByEmailAsync(email);
            if (user == null)
                return Json(true);
            return Json("ایمیل وارد شده در سایت موجود میباشد");
        }
  
        public async Task<IActionResult> IsUserNameInUse(string userName)
        {
            var user = await _userManager.FindByNameAsync(userName);
            if (user == null)
                return Json(true);
            return Json("نام کاربری وارد شده در سایت موجود میباشد");
        }
    }
}

using IdentitySample.Repositories;
using IdentitySample.Security.PhoneTotp;
using IdentitySample.Security.PhoneTotp.Providers;
using IdentitySample.ViewModel.Account;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;

namespace IdentitySample.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IMessageSender _messageSender;
        private readonly IPhoneTotpProviders _phoneTotpProvider;
        private readonly PhoneTotpOptions _phoneTotpOptions;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,
            IMessageSender messageSender, IPhoneTotpProviders phoneTotpProvider,
            IOptions<PhoneTotpOptions> phoneTotpOptions)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _messageSender = messageSender;
            _phoneTotpProvider = phoneTotpProvider;
            _phoneTotpOptions = phoneTotpOptions?.Value ?? new PhoneTotpOptions();
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
                            new { username = user.UserName, token = emailConfirmationToken },
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
        public async Task<IActionResult> Login(string returnUrl = null)
        {
            if (_signInManager.IsSignedIn(User))
                return RedirectToAction("Index", "Home");

            var model = new LoginViewModel()
            {
                ReturnUrl = returnUrl,
                ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList()
            };

            ViewData["ReturnUrl"] = returnUrl;
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            if (_signInManager.IsSignedIn(User))
                return RedirectToAction("Index", "Home");

            model.ReturnUrl = returnUrl;
            model.ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
            ViewData["ReturnUrl"] = returnUrl;

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
            //HttpContext.Response.Cookies.Delete("RVG");
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> IsEmailInUse(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return Json(true);
            return Json("ایمیل وارد شده در سایت موجود میباشد");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> IsUserNameInUse(string userName)
        {
            var user = await _userManager.FindByNameAsync(userName);
            if (user == null)
                return Json(true);
            return Json("نام کاربری وارد شده در سایت موجود میباشد");
        }

        [HttpPost]
        public IActionResult ExternalLogin(string provider, string returnUrl)
        {
            var redirectUrl = Url.Action("ExternalLoginCallBack", "Account",
                new { ReturnUrl = returnUrl });

            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return new ChallengeResult(provider, properties);
        }

        [HttpGet]
        public async Task<IActionResult> ExternalLoginCallBack(string returnUrl = null,
            string remoteError = null)
        {
            ViewData["returnUrl"] = returnUrl;
            returnUrl =
                (returnUrl != null && Url.IsLocalUrl(returnUrl)) ? returnUrl : Url.Content("~/");

            var loginViewModel = new LoginViewModel()
            {
                ReturnUrl = returnUrl,
                ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList()
            };

            if (remoteError != null)
            {
                ModelState.AddModelError("", $"Error : {remoteError}");
                return View("Login", loginViewModel);
            }

            var externalLoginInfo = await _signInManager.GetExternalLoginInfoAsync();
            if (externalLoginInfo == null)
            {
                ModelState.AddModelError("ErrorLoadingExternalLoginInfo", $"مشکلی پیش آمد");
                return View("Login", loginViewModel);
            }

            var signInResult = await _signInManager.ExternalLoginSignInAsync(externalLoginInfo.LoginProvider,
                externalLoginInfo.ProviderKey, false, true);

            if (signInResult.Succeeded)
            {
                return Redirect(returnUrl);
            }

            var email = externalLoginInfo.Principal.FindFirstValue(ClaimTypes.Email);

            if (email != null)
            {
                var user = await _userManager.FindByEmailAsync(email);

                if (user == null)
                    return View();

                await _userManager.AddLoginAsync(user, externalLoginInfo);
                await _signInManager.SignInAsync(user, false);

                return Redirect(returnUrl);
            }

            ViewData["ErrorMessage"] = $"دریافت کرد {externalLoginInfo.LoginProvider} نمیتوان اطلاعاتی از";
            return View("Login", loginViewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginCallBack(ExternalLoginCallBackViewModel model,
            string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                var loginViewModel = new LoginViewModel()
                {
                    ReturnUrl = returnUrl,
                    ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList()
                };

                var externalLoginInfo = await _signInManager.GetExternalLoginInfoAsync();
                if (externalLoginInfo?.Principal.FindFirstValue(ClaimTypes.Email) == null)
                {
                    ModelState.AddModelError("ErrorLoadingExternalLoginInfo", "مشکلی پیش آمد");
                    return View("Login", loginViewModel);
                }

                var email = externalLoginInfo?.Principal.FindFirstValue(ClaimTypes.Email);
                var user = await _userManager.FindByEmailAsync(email);

                if (user == null)
                {
                    var result = new IdentityResult();
                    user = new IdentityUser()
                    {
                        Email = email,
                        UserName = model.UserName,
                        EmailConfirmed = true
                    };

                    if (!string.IsNullOrEmpty(model.Password))
                        await _userManager.CreateAsync(user, model.Password);
                    else
                        await _userManager.CreateAsync(user);

                    if (result.Succeeded)
                    {
                        await _userManager.AddLoginAsync(user, externalLoginInfo);
                        await _signInManager.SignInAsync(user, false);

                        if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                            return Redirect(returnUrl);

                        return RedirectToAction("Index", "Home");
                    }

                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                }
                else
                {
                    ModelState.AddModelError("", "مشکلی پیش آمد");
                    return View("Login", loginViewModel);
                }
            }

            return View(model);
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var loginViewModel = new LoginViewModel()
                {
                    ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList()
                };

                ViewData["ErrorMessage"] =
                    "اگر ایمیل وارد شده معتبر باشد لینک فراموشی رمز عبور به ایمیل شما ارسال میشود.";

                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                    return View("Login", loginViewModel);

                var resetPasswordToken = await _userManager.GeneratePasswordResetTokenAsync(user);
                var resetPasswordUrl = Url.Action("ResetPassword", "Account",
                    new { email = user.Email, token = resetPasswordToken }, Request.Scheme);

                await _messageSender.SendEmailAsync(user.Email, "Reset Password Link",
                    $"لطفا برای تغییر رمز خود وارد این '{resetPasswordUrl}' شوید");

                return View("Login", loginViewModel);
            }

            return View();
        }

        [HttpGet]
        public IActionResult ResetPassword(string email, string token)
        {
            if (string.IsNullOrWhiteSpace(email) || (string.IsNullOrWhiteSpace(token)))
                return RedirectToAction("Index", "Home");

            var model = new ResetPasswordViewModel()
            {
                Email = email,
                Token = token
            };
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var loginViewModel = new LoginViewModel
                {
                    ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList()
                };

                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                    return RedirectToAction("Login", loginViewModel);

                var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
                if (result.Succeeded)
                {
                    ViewData["ErrorMessage"] = "پسورد شما با موفقیت تغییر یافت. لطفا مجددا وارد سایت شوید";
                    return View("Login", loginViewModel);
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }

            return View(model);
        }

        [HttpGet]
        public IActionResult SendTotpCode()
        {
            if (_signInManager.IsSignedIn(User))
                return RedirectToAction("Index", "Home");

            ViewData["SendTotpCodeErrorMessage"] = null;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SendTotpCode(SendTotpCodeViewModel viewModel)
        {
            if (_signInManager.IsSignedIn(User))
                return RedirectToAction("Index", "Home");
            if (ModelState.IsValid)
            {
                // Show expire time for user
                if (TempData.ContainsKey("PTC"))
                {
                    var totpTempDataModel = JsonSerializer
                        .Deserialize<PhoneTotpTempDataModel>(TempData["PTC"].ToString()!);

                    if (totpTempDataModel.ExpireTime >= DateTime.Now)
                    {
                        // returns a expire time as int for show in View
                        var differenceInSeconds = (int)(totpTempDataModel.ExpireTime - DateTime.Now).TotalSeconds;
                        ModelState.AddModelError("PhoneNumber", $"برای ارسال دوباره کد لطفا {differenceInSeconds} ثانیه صبرکنید.");
                        // For keep temp data after calling
                        TempData.Keep("PTC");
                        return View(viewModel);
                    }
                }

                var secretKey = Guid.NewGuid().ToString();
                var totpCode = _phoneTotpProvider.GenerateTotp(secretKey);
                var userExist = await _userManager.Users
                    .AnyAsync(user => user.PhoneNumber == viewModel.PhoneNumber);

                if (userExist)
                {
                    // TODO - Send Totp Code to user.
                }

                // Convert model to json as string
                TempData["PTC"] = JsonSerializer.Serialize(new PhoneTotpTempDataModel()
                {
                    SecretKey = secretKey,
                    PhoneNumber = viewModel.PhoneNumber,
                    ExpireTime = DateTime.Now.AddSeconds(_phoneTotpOptions.StepInSeconds)
                });

                // return RedirectToAction("VerifyTotpCode", "Account");
                return Content(totpCode);
            }

            ViewData["SendTotpCodeErrorMessage"] = null;
            return View(viewModel);
        }

        [HttpGet]
        public IActionResult VerifyTotpCode()
        {
            if (_signInManager.IsSignedIn(User))
                return RedirectToAction("Index", "Home");

            if (TempData.ContainsKey("PTC")) return NotFound();

            var totpTempDataModel = JsonSerializer
                      .Deserialize<PhoneTotpTempDataModel>(TempData["PTC"].ToString()!);
            if (totpTempDataModel.ExpireTime >= DateTime.Now)
            {
                ViewData["SendTotpCodeErrorMessage"] = "کد ارسال شده منقضی شده لطفا کد جدیدی دریافت کنید.";
                return RedirectToAction("SendTotpCode");
            }

            ViewData["SendTotpCodeErrorMessage"] = null;
            TempData.Keep("PTC");
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyTotpCode(VerifyTotpCodeViewModel viewModel)
        {
            if (_signInManager.IsSignedIn(User))
                return RedirectToAction("Index", "Home");

            if (TempData.ContainsKey("PTC")) return NotFound();

            if (ModelState.IsValid)
            {
                var totpTempDataModel = JsonSerializer
                      .Deserialize<PhoneTotpTempDataModel>(TempData["PTC"].ToString()!);
                if (totpTempDataModel.ExpireTime >= DateTime.Now)
                {
                    ViewData["SendTotpCodeErrorMessage"] = "کد ارسال شده منقضی شده لطفا کد جدیدی دریافت کنید.";
                    return RedirectToAction("SendTotpCode");
                }

                var user = await _userManager.Users
                    .Where(u => u.PhoneNumber == totpTempDataModel.PhoneNumber)
                    .FirstOrDefaultAsync();

                var result = _phoneTotpProvider.VerifyTotp(totpTempDataModel.SecretKey, viewModel.TotpCode);
                if (result.Succeeded)
                {
                    if (user == null)
                    {
                        ViewData["SendTotpCodeErrorMessage"] = "کاربری با شماره موبایل وارد شده یافت نشد.";
                        return RedirectToAction("SendTotpCode");
                    }

                    if (!user.PhoneNumberConfirmed)
                    {
                        ViewData["SendTotpCodeErrorMessage"] = "شماره مویال شما تایید نشده است.";
                        return RedirectToAction("SendTotpCode");
                    }

                    if (!await _userManager.IsLockedOutAsync(user))
                    {
                        await _userManager.ResetAccessFailedCountAsync(user);
                        await _signInManager.SignInWithClaimsAsync(user, false, new List<Claim>()
                        {
                            new Claim("UserPhone", user.PhoneNumber ?? "")
                        });

                        return RedirectToAction("Index", "Home");
                    }

                    ViewData["SendTotpCodeErrorMessage"] = "اکانت شما به دلیل ورود ناموفق تا مدت 5 دقیقه قفل شده است";
                    return RedirectToAction("SendTotpCode");
                }

                // lock account for 5 min
                if (user != null && user.PhoneNumberConfirmed && !await _userManager.IsLockedOutAsync(user))
                {
                    await _userManager.AccessFailedAsync(user);
                }

                ViewData["SendTotpCodeErrorMessage"] = "کد ارسال شده منقضی شده لطفا کد جدیدی دریافت کنید.";
                return RedirectToAction("SendTotpCode");
            }

            ViewData["SendTotpCodeErrorMessage"] = null;
            return View(viewModel);
        }
    }
}
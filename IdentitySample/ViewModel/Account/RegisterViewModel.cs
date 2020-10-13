using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace IdentitySample.ViewModel.Account
{
    public class RegisterViewModel
    {
        [Display(Name = "نام کاربری")]
        [Required(ErrorMessage = "نام کاربری را وارد کنید")]
        [Remote("IsUserNameInUse", "Account", HttpMethod = "POST",
            AdditionalFields = "__RequestVerificationToken")]
        public string UserName { get; set; }

        [Display(Name = "ایمیل")]
        [Required(ErrorMessage = "ایمیل را وارد کنید")]
        [DataType(DataType.EmailAddress)]
        [Remote("IsEmailInUse", "Account", HttpMethod = "POST",
            AdditionalFields = "__RequestVerificationToken")]
        public string Email { get; set; }

        [Display(Name = "رمز عبور")]
        [Required(ErrorMessage = "رمز عبور را وارد کنید")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Display(Name = "تکرار رمز عبور")]
        [Required(ErrorMessage = "تکرار رمز عبور را وارد کنید")]
        [Compare(nameof(Password))]
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; }
    }
}
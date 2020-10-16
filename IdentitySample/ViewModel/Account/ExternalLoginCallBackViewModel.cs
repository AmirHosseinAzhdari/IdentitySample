using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace IdentitySample.ViewModel.Account
{
    public class ExternalLoginCallBackViewModel
    {
        [Display(Name = "نام کاربری")]
        [Required(ErrorMessage = "نام کاربری را وارد کنید")]
        [Remote("IsUserNameInUse", "Account", HttpMethod = "POST",
            AdditionalFields = "__RequestVerificationToken")]
        public string UserName { get; set; }

        [Display(Name = "رمز عبور")]
        [DataType(DataType.Password)]
        [MinLength(6, ErrorMessage = "رمز عبور حداقل باید {1} کاراکتر باشد")]
        public string Password { get; set; }

        [Display(Name = "تکرار رمز عبور")]
        [Compare(nameof(Password), ErrorMessage = "رمز عبور و تکرار آن مطابقت ندارد")]
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; }
    }
}
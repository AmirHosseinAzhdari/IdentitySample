using System.ComponentModel.DataAnnotations;

namespace IdentitySample.ViewModel.Account
{
    public class ResetPasswordViewModel
    {
        [Display(Name = "رمز عبور")]
        [Required(ErrorMessage = "رمز عبور را وارد کنید")]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; }

        [Display(Name = "تکرار رمز عبور")]
        [Required(ErrorMessage = "تکرار رمز عبور را وارد کنید")]
        [Compare(nameof(NewPassword), ErrorMessage = "رمز عبور و تکرار آن مطابقت ندارد")]
        [DataType(DataType.Password)]
        public string ConfirmNewPassword { get; set; }

        [Required]
        public string Token { get; set; }

        [Required]
        public string Email { get; set; }
    }
}
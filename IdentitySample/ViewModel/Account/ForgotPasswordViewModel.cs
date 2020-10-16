using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace IdentitySample.ViewModel.Account
{
    public class ForgotPasswordViewModel
    {
        [Display(Name = "ایمیل")]
        [Required(ErrorMessage = "ایمیل را وارد کنید")]
        [DataType(DataType.EmailAddress, ErrorMessage = "ایمیل وارد شده صحیح نمیباشد")]
        public string Email { get; set; }
    }
}
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;

namespace IdentitySample.ViewModel.Account
{
    public class LoginViewModel
    {
        [Required(ErrorMessage ="نام کاربری را وارد کنید")]
        [Display(Name ="نام کاربری")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "رمز عبور را وارد کنید")] 
        [Display(Name = "رمز عبور")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Display(Name = "مرا به خاطر بسپارید")]
        public bool RememberMe { get; set; }

        public string ReturnUrl { get; set; }
        public IList<AuthenticationScheme> ExternalLogins { get; set; }
    }
}

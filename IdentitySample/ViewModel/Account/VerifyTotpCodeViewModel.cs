using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace IdentitySample.ViewModel.Account
{
    public class VerifyTotpCodeViewModel
    {
        [Display(Name = "کد ارسال شده")]
        [Required(ErrorMessage = "وارد کردن {0} الزامی است")]
        [MaxLength(6, ErrorMessage = "بو نمیتواند بیشتر از بیبله کاراکتر باشد")]
        public string TotpCode { get; set; }
    }
}

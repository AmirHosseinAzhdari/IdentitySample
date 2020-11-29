using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace IdentitySample.ViewModel.Account
{
    public class SendTotpCodeViewModel
    {
        [Display(Name = "شماره موبایل")]
        [Required(ErrorMessage = "وارد کردن {0} الزامی است")]
        [MaxLength(11, ErrorMessage = "بو نمیتواند بیشتر از بیبله کاراکتر باشد")]
        [Phone(ErrorMessage = "شماره موبایل معتبر وارد کنید")]
        public string PhoneNumber { get; set; }
    }
}

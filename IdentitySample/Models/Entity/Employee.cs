using System.ComponentModel.DataAnnotations;

namespace IdentitySample.Models.Entity
{
    public class Employee
    {
        [Key]
        public int Id { get; set; }

        [StringLength(64)]
        [Required(ErrorMessage = "لطفا نام را وارد کنید")]
        [Display(Name = "نام")]
        public string Name { get; set; }

        [StringLength(64)]
        [Required(ErrorMessage = "لطفا نام خانوادگی را وارد کنید")]
        [Display(Name = "نام خانوادگی")]
        public string LastName { get; set; }

        [StringLength(64)]
        [Required(ErrorMessage = "لطفا شهر را وارد کنید")]
        [Display(Name = "شهر")]
        public string City { get; set; }

        [StringLength(32)]
        [Display(Name = "نقش")]
        [Required(ErrorMessage = "لطفا نقش را وارد کنید")]
        public string Gender { get; set; }
    }
}
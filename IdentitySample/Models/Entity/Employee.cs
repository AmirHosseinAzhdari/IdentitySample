using System.ComponentModel.DataAnnotations;

namespace IdentitySample.Models.Entity
{
    public class Employee
    {
        [Key]
        public int Id { get; set; }
        
        [StringLength(64)]
        [Required(ErrorMessage = "Please Inter Name")]
        public string Name { get; set; }
        
        [StringLength(64)]
        [Required(ErrorMessage = "Please Inter LastName")]
        public string LastName { get; set; }
        
        [StringLength(64)]
        [Required(ErrorMessage = "Please Inter City")]
        public string City { get; set; }
        
        [StringLength(32)]
        [Required(ErrorMessage = "Please Inter Gender")]
        public string Gender { get; set; }
    }
}
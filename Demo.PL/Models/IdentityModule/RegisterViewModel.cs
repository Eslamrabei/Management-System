using System.ComponentModel.DataAnnotations;

namespace Demo.PL.Models.IdentityModule
{
    public class RegisterViewModel
    {
        [Required(ErrorMessage = "Username can not be null")]
        [MaxLength(50)]
        public string UserName { get; set; }
        [Required(ErrorMessage = "Firstname can not be null")]
        [MaxLength(50)]
        public string FirstName { get; set; }
        [Required(ErrorMessage = "Lastname can not be null")]
        [MaxLength(50)]
        public string LastName { get; set; }
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }
        [DataType(DataType.Password)]
        public string Password { get; set; }
        [DataType(DataType.Password)]
        [Compare(nameof(Password))]
        public string ConfirmPassword { get; set; }
        [Display(Name = "Phone Number")]
        public string PhoneNumber { get; set; }
        public bool isAgree { get; set; }
    }
}

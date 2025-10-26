using Microsoft.AspNetCore.Mvc.Rendering;
using System.ComponentModel.DataAnnotations;

namespace Demo.PL.Models.RoleModule
{
    public class AssignRoleToUserViewModel
    {
        [Required]
        public string RoleId { get; set; }

        public string RoleName { get; set; }

        [Required(ErrorMessage = "Please select a user")]
        [Display(Name = "Select User")]
        public string SelectedUserId { get; set; }

        public List<SelectListItem> Users { get; set; } = new List<SelectListItem>();
    }
}

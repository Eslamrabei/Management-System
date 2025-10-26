using System.ComponentModel;

namespace Demo.PL.Models.UserModule
{
    public class UserViewModel
    {
        public string Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        [DisplayName("Phone Number")]
        public string PhoneNumber { get; set; }
        public IEnumerable<string> Roles { get; set; } = new List<string>();

        public UserViewModel()
        {
            Id = Guid.NewGuid().ToString();
        }
    }
}

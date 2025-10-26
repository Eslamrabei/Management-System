namespace Demo.PL.Models.RoleModule
{
    public class RoleViewModel
    {
        public string Id { get; set; }
        public string Name { get; set; } = null!;
        public RoleViewModel() => Id = Guid.NewGuid().ToString();

    }
}

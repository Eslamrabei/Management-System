namespace RouteG03.BLL.Dtos.DepartmentsDtos
{
    public class CreateDepartmentDto
    {
        public string Name { get; set; } = null!;
        public string Code { get; set; } = null!;
        public string? Description { get; set; }
        public DateOnly? DateOfCreation { get; set; }

    }
}

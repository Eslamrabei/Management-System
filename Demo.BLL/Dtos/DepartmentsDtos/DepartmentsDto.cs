namespace RouteG03.BLL.Dtos.DepartmentsDtos
{
    public class DepartmentsDto
    {
        public int Id { get; set; }
        public string Name { get; set; } = null!;
        public string Code { get; set; } = null!;
        public string? Description { get; set; }
        public DateOnly DateOfCreation { get; set; }


    }
}

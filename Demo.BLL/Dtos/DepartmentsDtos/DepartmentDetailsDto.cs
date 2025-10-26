namespace RouteG03.BLL.Dtos.DepartmentsDtos
{
    public class DepartmentDetailsDto
    {
        public int Id { get; set; }
        public int CreatedBy { get; set; }  //User ID
        public DateOnly? CreatedOn { get; set; }
        public int LastModifiedBy { get; set; }
        public DateOnly? LastModifiedOn { get; set; }
        public bool IsDeleted { get; set; }
        public string Name { get; set; } = null!;
        public string Code { get; set; } = null!;
        public string? Description { get; set; }
    }
}

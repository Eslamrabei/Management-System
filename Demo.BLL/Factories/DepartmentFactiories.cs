using RouteG03.BLL.Dtos.DepartmentsDtos;
using RouteG03.DAL.Models.DepartmentModules;

namespace RouteG03.BLL.Factories
{
    public static class DepartmentFactories
    {
        public static DepartmentsDto ReturnToDepartmentsDto(this Department d)
        {
            return new DepartmentsDto()
            {
                Id = d.Id,
                Code = d.Code,
                Name = d.Name,
                Description = d.Description,
                DateOfCreation = d.CreatedOn.HasValue ? DateOnly.FromDateTime(d.CreatedOn.Value) : default
            };
        }

        public static DepartmentDetailsDto ReturnToDepartmentDetailsDto(this Department d)
        {
            return new DepartmentDetailsDto()
            {
                Id = d.Id,
                Name = d.Name,
                Code = d.Code,
                Description = d.Description,
                CreatedBy = d.CreatedBy,
                LastModifiedBy = d.LastModifiedBy,
                IsDeleted = d.IsDeleted,
                CreatedOn = d.CreatedOn.HasValue ? DateOnly.FromDateTime(d.CreatedOn.Value) : default,
                LastModifiedOn = d.LastModifiedOn.HasValue ? DateOnly.FromDateTime(d.LastModifiedOn.Value) : default

            };
        }

        public static Department ToEntity(this CreateDepartmentDto create)
        {
            return new Department()
            {
                Name = create.Name,
                Code = create.Code,
                Description = create.Description,
                CreatedOn = create.DateOfCreation.HasValue ?
                create.DateOfCreation.Value.ToDateTime(new TimeOnly())
                : default
            };
        }

        public static Department ToUpdateEntity(this UpdatedDepartmentDto updated)
        {
            return new Department()
            {
                Id = updated.Id,
                Name = updated.Name,
                Code = updated.Code,
                Description = updated.Description,
                CreatedOn = updated.DateOfCreation.HasValue
                ? updated.DateOfCreation.Value.ToDateTime(new TimeOnly())
                : default
            };
        }
    }
}

using AutoMapper;
using Microsoft.AspNetCore.Http;
using RouteG03.DAL.Models.EmployeeModules;

namespace Demo.BLL.Mapping
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<Employee, EmployeesDto>()
                .ForMember(dest => dest.Gender, opt => opt.MapFrom(src => src.Gender.ToString()))
                .ForMember(dest => dest.EmployeeType, opt => opt.MapFrom(src => src.EmployeeType.ToString()))
                .ForMember(dest => dest.Department, options => options.MapFrom(src => src.Department != null ? src.Department.Name : null));

            CreateMap<Employee, EmployeeDetailsDto>()
                .ForMember(dest => dest.Gender, opt => opt.MapFrom(src => src.Gender.ToString()))
                .ForMember(dest => dest.EmployeeType, opt => opt.MapFrom(src => src.EmployeeType.ToString()))
                .ForMember(dest => dest.HiringDate, opt => opt.MapFrom(src => DateOnly.FromDateTime(src.HiringDate)))
                .ForMember(dest => dest.Department, options => options.MapFrom(src => src.Department != null ? src.Department.Name : null));



            CreateMap<CreateEmployeeDto, Employee>()
                .ForMember(dest => dest.HiringDate, opt => opt.MapFrom(src => src.HiringDate.ToDateTime(TimeOnly.MinValue)))
                .ForMember(dest => dest.ImageName, options => options.MapFrom(src => src.Image));

            CreateMap<UpdateEmployeeDto, Employee>()
                .ForMember(dest => dest.HiringDate, opt => opt.MapFrom(src => src.HiringDate.ToDateTime(TimeOnly.MinValue)));


        }
        public IFormFile? CreateIFormFileFromString(string filePathString)
        {
            if (string.IsNullOrEmpty(filePathString))
            {
                return null;
            }

            var filePath = Path.Combine(Directory.GetCurrentDirectory(), filePathString);
            if (File.Exists(filePath))
            {
                using var stream = new FileStream(filePath, FileMode.Open);
                return new FormFile(stream, 0, stream.Length, "name", Path.GetFileName(filePath));
            }
            return null;
        }
    }

}

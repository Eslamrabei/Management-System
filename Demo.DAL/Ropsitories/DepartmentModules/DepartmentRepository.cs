using Demo.DAL.Ropsitories.Shared;
using RouteG03.DAL.Data.Context;
using RouteG03.DAL.Models.DepartmentModules;

namespace RouteG03.DAL.Ropsitories.DepartmentModules
{
    public class DepartmentRepository(AppDbContext _context) : GenericRepository<Department>(_context), IDepartmentRepository
    {

    }
}

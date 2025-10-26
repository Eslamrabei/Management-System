using Demo.DAL.Ropsitories.Shared;
using RouteG03.DAL.Data.Context;
using RouteG03.DAL.Models.EmployeeModules;

namespace RouteG03.DAL.Ropsitories.EmployeeModules
{
    public class EmployeeRepostiory(AppDbContext dbContext) : GenericRepository<Employee>(dbContext), IEmployeeRepository
    {

    }
}

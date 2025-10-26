using RouteG03.DAL.Ropsitories.DepartmentModules;
using RouteG03.DAL.Ropsitories.EmployeeModules;

namespace Demo.DAL.Ropsitories.Shared
{
    public interface IUniteOfWork
    {
        IEmployeeRepository EmployeeRepository { get; }
        IDepartmentRepository DepartmentRepository { get; }

        int SaveChanges();
    }
}

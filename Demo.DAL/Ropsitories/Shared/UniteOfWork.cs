using RouteG03.DAL.Data.Context;
using RouteG03.DAL.Ropsitories.DepartmentModules;
using RouteG03.DAL.Ropsitories.EmployeeModules;

namespace Demo.DAL.Ropsitories.Shared
{
    public class UniteOfWork : IUniteOfWork
    {
        private readonly Lazy<IEmployeeRepository> _employeeRepository;
        private readonly Lazy<IDepartmentRepository> _departmentRepository;
        private readonly AppDbContext _dbContext;
        public UniteOfWork(IEmployeeRepository employeeRepository
            , IDepartmentRepository departmentRepository
            , AppDbContext dbContext)
        {
            _dbContext = dbContext;
            _employeeRepository = new Lazy<IEmployeeRepository>(() => new EmployeeRepostiory(_dbContext));
            _departmentRepository = new Lazy<IDepartmentRepository>(() => new DepartmentRepository(_dbContext));
        }

        public IEmployeeRepository EmployeeRepository => _employeeRepository.Value;

        public IDepartmentRepository DepartmentRepository => _departmentRepository.Value;

        public int SaveChanges()
        {
            return _dbContext.SaveChanges();
        }
    }
}

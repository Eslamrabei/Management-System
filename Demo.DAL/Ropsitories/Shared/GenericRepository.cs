
using Microsoft.EntityFrameworkCore;
using RouteG03.DAL.Data.Context;
using System.Linq.Expressions;

namespace Demo.DAL.Ropsitories.Shared
{
    public class GenericRepository<TEntity>(AppDbContext dbContext) : IGenericRepository<TEntity> where TEntity : BaseEntity
    {
        // GetAll
        public IEnumerable<TEntity> GetAll(bool withTraking = false)
        {
            if (withTraking)
                return dbContext.Set<TEntity>().Where(enityt => !enityt.IsDeleted).ToList();
            else
                return dbContext.Set<TEntity>().AsNoTracking().Where(enityt => !enityt.IsDeleted).ToList();
        }
        // Get By Id 
        public TEntity? GetById(int id)
        {
            return dbContext.Set<TEntity>().Find(id);
        }
        // ADD
        public void Add(TEntity entity)
        {
            dbContext.Set<TEntity>().Add(entity);
        }
        //UPDATE
        public void Update(TEntity entity)
        {
            dbContext.Set<TEntity>().Update(entity);
        }
        //DELETE
        public void Delete(TEntity entity)
        {
            dbContext.Set<TEntity>().Remove(entity);
        }

        public IEnumerable<TEntity> GetAll(Expression<Func<TEntity, bool>> Predicate)
        {
            return dbContext.Set<TEntity>().Where(Predicate).Where(entity => !entity.IsDeleted).ToList();
        }
    }
}

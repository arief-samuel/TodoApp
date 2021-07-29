using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using TodoApp.Models;

namespace TodoApp.Data
{
    public class TodoAppDbContext : IdentityDbContext
    {
        public DbSet<Item> Items { get; set; }

        public TodoAppDbContext(DbContextOptions<TodoAppDbContext> options) : base(options)
        {
        }
    }
}
using Demo.BLL.AttachmentsService;
using Demo.BLL.EmailSettings;
using Demo.BLL.Mapping;
using Demo.DAL.Models.IdentityModule;
using Demo.DAL.Ropsitories.Shared;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using RouteG03.BLL.Services.DepartmentServices;
using RouteG03.BLL.Services.EmployeeServices;
using RouteG03.DAL.Data.Context;
using RouteG03.DAL.Ropsitories.DepartmentModules;
using RouteG03.DAL.Ropsitories.EmployeeModules;

namespace Demo.PL
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddDbContext<AppDbContext>(options =>
            {
                options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
            });


            builder.Services.AddControllersWithViews();

            builder.Services.AddScoped<IDepartmentRepository, DepartmentRepository>();
            builder.Services.AddScoped<IDepartmentServices, DepartmentServices>();
            builder.Services.AddScoped<IEmployeeRepository, EmployeeRepostiory>();
            builder.Services.AddScoped<IEmployeeServices, EmployeeServices>();
            builder.Services.AddScoped<IUniteOfWork, UniteOfWork>();
            builder.Services.AddScoped<IEmailSetting, EmailSetting>();
            builder.Services.AddScoped<IAttachmentservice, AttachmentService>();
            builder.Services.AddAutoMapper(m => m.AddProfile(new MappingProfile()));
            builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
            .AddEntityFrameworkStores<AppDbContext>()
            .AddDefaultTokenProviders();

            builder.Services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddGoogle(options =>
            {
                options.ClientId = builder.Configuration["Authentication:Google:ClientId"]!;
                options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"]!;
            })
            .AddFacebook(options =>
            {
                options.ClientId = builder.Configuration["Authentication:Facebook:AppId"]!;
                options.ClientSecret = builder.Configuration["Authentication:Facebook:AppSecret"]!;
            });


            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.MapStaticAssets();
            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Account}/{action=LogIn}/{id?}")
                .WithStaticAssets();

            app.Run();
        }
    }
}

using IdentitySample.Models.Context;
using IdentitySample.PersianTranslation.Identity;
using IdentitySample.Repositories;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using IdentitySample.Security.Default;
using IdentitySample.Security.DynamicRole;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using IdentitySample.Security.PhoneTotp.Providers;
using IdentitySample.Security.PhoneTotp;

namespace IdentitySample
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews()
                .AddRazorRuntimeCompilation();

            //Connection String
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(Configuration.GetConnectionString("Default")));

            #region Authentication
            //Authentication
            services.AddAuthentication()
                .AddGoogle(options =>
                {
                    options.ClientId = Configuration["GoogleAuthentication:ClientId"];
                    options.ClientSecret = Configuration["GoogleAuthentication:ClientSecret"];
                });
            #endregion

            #region Identity
            services.AddIdentity<IdentityUser, IdentityRole>(options =>
                {
                    options.Password.RequiredUniqueChars = 0;
                    options.User.RequireUniqueEmail = true;

                    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
                })
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders()
                .AddErrorDescriber<PersianIdentityErrorDescriber>();
            #endregion

            services.ConfigureApplicationCookie(options =>
            {
                options.AccessDeniedPath = "/Account/AccessDenied";
                options.Cookie.Name = "IdentityProj";
                options.LoginPath = "/Account/Login";
                options.ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter;
            });

            services.Configure<SecurityStampValidatorOptions>(option =>
            {
                option.ValidationInterval = TimeSpan.FromSeconds(10);
            });        

            #region Authorization
            services.AddAuthorization(options =>
            {
                options.AddPolicy("EmployeeListPolicy", policy =>
                    policy.RequireClaim(ClaimTypesStore.EmployeeList, true.ToString()
                    ));

                options.AddPolicy("ClaimOrRole", policy =>
                     policy.RequireAssertion(context =>
                         context.User.HasClaim(ClaimTypesStore.EmployeeList, true.ToString()) ||
                         context.User.IsInRole("Admin")
                         ));

                options.AddPolicy("ClaimRequirement", policy =>
                    policy.Requirements.Add(new ClaimRequirement(ClaimTypesStore.EmployeeList,
                        true.ToString())));

                options.AddPolicy("DynamicRole", policy =>
                    policy.Requirements.Add(new DynamicRoleRequirement()));
            });
            #endregion

            services.AddMemoryCache();
            services.AddHttpContextAccessor();

            //Transient
            services.AddTransient<IUtilities, Utilities>();
            services.AddTransient<IPhoneTotpProviders, PhoneTotpProviders>();
            services.Configure<PhoneTotpOptions>(options =>
            {
                options.StepInSeconds = 30;
            });
            //Scoped
            services.AddScoped<IMessageSender, MessageSender>();
            services.AddScoped<IAuthorizationHandler, DynamicRoleHandler>();
            //Singleton
            services.AddSingleton<IAuthorizationHandler, ClaimHandler>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
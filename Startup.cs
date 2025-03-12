// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using System;
using System.Threading.Tasks;

namespace WebApp_OpenIDConnect_DotNet
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
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
                // Handling SameSite cookie according to https://docs.microsoft.com/en-us/aspnet/core/security/samesite?view=aspnetcore-3.1
                options.HandleSameSiteCookieCompatibility();
            });

            services.AddDistributedMemoryCache(); // Enables session caching
            services.AddSession(); // Enables session storage

            // Configure Azure AD B2C authentication
            services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
                .AddMicrosoftIdentityWebApp(Configuration.GetSection(Constants.AzureAdB2C))
                // Required for an access_token to be issued
                // Scopes (list of strings) can be defined here, or in "Scope", in appsettings
                .EnableTokenAcquisitionToCallDownstreamApi(new string[] {})
                .AddDistributedTokenCaches();

            // Explicitly configure OpenIdConnectOptions to add the query parameter
            services.Configure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
            {
                // Required for an access_token to be issued
                options.Events.OnAuthorizationCodeReceived = async context => {};

                options.Events.OnTokenResponseReceived = context =>
                {
                    Console.WriteLine($"Access token: {context.TokenEndpointResponse?.AccessToken}");
                    Console.WriteLine($"ID token: {context.TokenEndpointResponse?.IdToken}");
                    return Task.CompletedTask;
                };

                options.Events.OnRedirectToIdentityProvider = context =>
                {
                    // Add a custom query parameter
                    context.ProtocolMessage.SetParameter("appUrl", "https://jwt.ms");
                    return Task.CompletedTask;
                };
            });

            services.AddControllersWithViews()
                .AddMicrosoftIdentityUI();

            services.AddRazorPages();

            // Adding appsettings section into IOptions
            services.AddOptions();
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

            // Default value false (https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/wiki/PII)
            if (Configuration.GetSection(Constants.AzureAdB2C).GetValue<bool>("EnablePiiLogging") == true) {
                Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            // Enable session storage for distributed memory cache
            app.UseSession();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });
        }
    }
}
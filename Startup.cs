using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;

namespace OAuthGithubDemo
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
            services.AddHttpContextAccessor();
            services.AddMemoryCache();

            services.AddAuthentication(options =>
            {
                //options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                //options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

                options.DefaultChallengeScheme = "OAuth";
            })
            .AddOAuth("OAuth", options =>
            {
                // All options are set at runtime by tenant settings
            })
            .AddCookie("OAuth.Cookie", options =>
            {
                options.Cookie.Name = "OAuth-cookiename";
                options.Cookie.SameSite = SameSiteMode.None;

                options.LoginPath = "/account/login";
                options.AccessDeniedPath = "/account/login";
            });

            services.AddScoped<IOptionsMonitor<OAuthOptions>, MyOptionsMonitor>();
            services.AddScoped<IConfigureOptions<OAuthOptions>, ConfigureMyOptions>();

            services.AddMvc(options => options.Filters.Add(new AuthorizeFilter()))
                .SetCompatibilityVersion(CompatibilityVersion.Version_2_1);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseAuthentication();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        public class ConfigureMyOptions : IConfigureNamedOptions<OAuthOptions>
        {
            private HttpContext _httpContext;
            private IDataProtectionProvider _dataProtectionProvider;
            private OAuthOptions myCurrentOptions;

            public ConfigureMyOptions(IHttpContextAccessor contextAccessor, IDataProtectionProvider dataProtectionProvider)
            {
                _httpContext = contextAccessor.HttpContext;
                _dataProtectionProvider = dataProtectionProvider;
            }

            public void Configure(string name, OAuthOptions options)
            {
                //var tenant = _httpContext.ResolveTenant();

                // in my code i use tenant.Settings for these:

                //options.DataProtectionProvider = _dataProtectionProvider.CreateProtector(tenantId.ToString());

                options.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
                options.TokenEndpoint = "https://github.com/login/oauth/access_token";
                options.UserInformationEndpoint = "https://api.github.com/user";

                options.ClientId = "redacted";
                options.ClientSecret = "redacted";

                options.Scope.Add("openid");
                options.Scope.Add("write:gpg_key");
                options.Scope.Add("repo");
                options.Scope.Add("read:user");

                options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
                options.ClaimActions.MapJsonKey("External", "id");

                options.SignInScheme = "OAuth.Cookie";
                options.CallbackPath = new PathString("/signin");

                options.SaveTokens = true;

                options.Events = new OAuthEvents
                {
                    OnCreatingTicket = _onCreatingTicket,
                    OnTicketReceived = _onTicketReceived
                };

                myCurrentOptions = options;
            }

            public void Configure(OAuthOptions options) => Configure(Options.DefaultName, options);

            private static async Task _onCreatingTicket(OAuthCreatingTicketContext context)
            {
                // Get the external user id and set it as a claim
                using (var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint))
                {
                    request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);

                    using (var response = await context.Backchannel.SendAsync(request, context.HttpContext.RequestAborted))
                    {
                        response.EnsureSuccessStatusCode();
                        var user = JObject.Parse(await response.Content.ReadAsStringAsync());

                        context.RunClaimActions(user);
                    }
                }
            }

            private static Task _onTicketReceived(TicketReceivedContext context)
            {
                context.Properties.IsPersistent = true;
                context.Properties.AllowRefresh = true;
                context.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(30);

                return Task.CompletedTask;
            }
        }

        public class MyOptionsMonitor : IOptionsMonitor<OAuthOptions>
        {
            //  private readonly TenantContext<Tenant> _tenantContext;
            private readonly IOptionsFactory<OAuthOptions> _optionsFactory;
            private readonly IMemoryCache _cache;

            public MyOptionsMonitor(
                //  TenantContext<Tenant> tenantContext,
                IOptionsFactory<OAuthOptions> optionsFactory,
                IMemoryCache cache)
            {
                //   _tenantContext = tenantContext;
                _optionsFactory = optionsFactory;
                _cache = cache;
            }

            public OAuthOptions CurrentValue => Get(Options.DefaultName);

            public OAuthOptions Get(string name)
            {
                //var key = $"{_tenantContext.Tenant.Id}{name}";
                return _cache.GetOrCreate($"{name}", cache => _optionsFactory.Create(name));
            }

            public IDisposable OnChange(Action<OAuthOptions, string> listener)
            {
                return null;
            }
        }
    }
}

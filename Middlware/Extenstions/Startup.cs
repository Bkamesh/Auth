using Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Middlware.Extenstions
{
    public static class Startup
    {
        public static void AddCustomMiddleware(this IApplicationBuilder app, IConfiguration configuration)
        {
            var jwtSettings = configuration.GetSection("JwtSettings").Get<JwtSettings>();
            var regex = configuration.GetValue<string>("Regex:Expression") ?? "";

            app.UseCors("AllowSpecificOrigin");

            app.UseMiddleware<JwtMiddleware>(jwtSettings?.SecretKey, jwtSettings?.Issuer, jwtSettings?.Audience,regex);

            app.UseForwardedHeaders();
        }


        public static void AddCustomAuthentication(this IServiceCollection services, IConfiguration configuration)
        {

            var jwtSettings = configuration.GetSection("JwtSettings").Get<JwtSettings>();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtSettings?.Issuer??"",
                    ValidAudience = jwtSettings?.Audience??"",
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings?.SecretKey??""))
                };
            });

            services.AddAuthorization(options =>
            {
                options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
                options.AddPolicy("UserOnly", policy => policy.RequireRole("User"));
            });
        }

        public static void AddCorsandForwardHeaders(this IServiceCollection services, IConfiguration configuration)
        {
            var origins = (configuration.GetValue<string>("CrosOrigin")?? "").Split(';');

            services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
            });

            services.AddCors(options =>
            {
                options.AddPolicy("AllowSpecificOrigin",
                    builder => builder
                        .WithOrigins(origins)
                        .SetIsOriginAllowed(origin => new[] { origin }.Contains(origin))
                        .AllowCredentials()
                        .AllowAnyHeader()
                        .AllowAnyMethod()
                        .WithExposedHeaders("Custom-Auth-Token"));
            });
        }
    }
}

using Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;

public class JwtMiddleware
{
    private readonly RequestDelegate _next;
    private readonly string _secretKey;
    private readonly string _issuer;
    private readonly string _audience;
    public static string? _regexexpression;

    public JwtMiddleware(RequestDelegate next, string secretKey, string issuer, string audience,string RegexExpression)
    {
        _next = next;
        _secretKey = secretKey;
        _issuer = issuer;
        _audience = audience;
        _regexexpression = RegexExpression;
       
    }

    public async Task Invoke(HttpContext context)
    {
        
        var ipAddress = GetDynamicIp(context);

        if (ipAddress == "::1" ) //|| ipAddress != "127.0.0.1"
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access Denied: Unauthorized IP Address.");
            return;
        }

        await _next(context);
    }

    #region Ip Validation
    public static string GetDynamicIp(HttpContext context)
    {
        var ipAddress = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();

        if (string.IsNullOrEmpty(ipAddress) && context.Connection.RemoteIpAddress != null)
        {
            ipAddress = context.Connection.RemoteIpAddress.ToString() ?? "";
        }

        var regex_e = _regexexpression?.Split(';') ?? [""];

        foreach (var regex in regex_e)    
        {
            Regex regex_condition = new Regex(regex);
            if (regex_condition.IsMatch(ipAddress))
            {
                return ipAddress;
            }
        }
            return "::1";
    }
    #endregion

    #region MIDDLEWARE AUTHENTICATION
        public static ClaimsPrincipal ValidateToken(string token, string secretKey, string issuer, string audience)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateAudience = true,
                ValidAudience = audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero 
            };

            try
            {
                return tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
            }
            catch
            {
                return null; 
            }
        }
#endregion

#region Generate Token
public static string GenerateToken(string username, string SecretKey, string Issuer, string Audience, int ValidationTime)
    {
        var securityKey = Encoding.UTF8.GetBytes(SecretKey);
        var credentials = new SigningCredentials(new SymmetricSecurityKey(securityKey), SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Role, "Admin") 
        };

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddDays(ValidationTime),
            Issuer = Issuer,
            Audience = Audience,
            SigningCredentials = credentials
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
    #endregion
}

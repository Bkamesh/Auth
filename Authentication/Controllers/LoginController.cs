using Authentication;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using LoginRequest = Authentication.LoginRequest;

[Route("[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _configuration;

    private readonly JwtSettings _jwtSettings;

    private readonly CookieSettings _cookieOptions;
    public AuthController (IConfiguration configuration)
    {
        _configuration = configuration;
        _jwtSettings = _configuration.GetSection("JwtSettings").Get<JwtSettings>() ?? new JwtSettings();
        _cookieOptions = _configuration.GetSection("CookieSettings").Get<CookieSettings>() ?? new CookieSettings();
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {

        if (request.Username == "testuser" && request.Password == "password")
        {
            

            var token = JwtMiddleware.GenerateToken(request.Username, _jwtSettings.SecretKey ?? "", _jwtSettings.Issuer, _jwtSettings.Audience,_jwtSettings.TokenLifetime);

            //var cookieOptions = new CookieOptions
            //{
            //    HttpOnly = _cookieOptions.HttpOnly,
            //    Secure = _cookieOptions.Secure,
            //    Expires = DateTime.UtcNow.AddDays(_cookieOptions.ExpirationTime),
            //    SameSite = SameSiteMode.None
            //};
            //Response.Cookies.Append("AuthToken", token, cookieOptions);
            //--->cross site cookies are blocked browsers so dropping this method even though same site is none

            Response.Headers.Add("Custom-Auth-Token", token);

            return Ok(new { Message = "Login successful."});
        }
        return Unauthorized(new { Message = "Invalid username or password." });
    }
}

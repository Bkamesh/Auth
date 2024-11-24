using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;

namespace Authentication.Controllers
{
    [Authorize(policy: "AdminOnly")]
    [ApiController]
    [Route("[controller]")]
    public class UserController : ControllerBase
    {

        public UserController()
        {
            
        }

        [HttpGet(Name = "GetYourIp")]
        public IActionResult Get()
        {

            var ipAddress = JwtMiddleware.GetDynamicIp(HttpContext);
            return Ok(ipAddress);
        }
    }
}

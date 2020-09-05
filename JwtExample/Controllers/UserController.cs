using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using JwtExample.Configs;
using JwtExample.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace JwtExample.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly JwtSecurityTokenHandler jwtSecurityTokenHandler;
        private readonly SigningCredentials signingCredentials;
        private readonly IConfiguration configuration;
        public UserController(IConfiguration config)
        {
            configuration = config;
           
             var key = Encoding.ASCII.GetBytes(configuration.GetValue<string>("SecretKey"));
            SymmetricSecurityKey symmetricSecurityKey = new SymmetricSecurityKey(key);
            signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
        }
        
        [AllowAnonymous]
        [HttpGet("RequestToken")]
        public JsonResult RequestToken()
        {
            DateTime utcNow = DateTime.UtcNow;

            List<Claim> claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, utcNow.ToString())
            };

            DateTime expiredDateTime = utcNow.AddDays(1);

            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            string token = jwtSecurityTokenHandler.WriteToken(new JwtSecurityToken(claims: claims, expires: expiredDateTime,notBefore:utcNow,  signingCredentials: signingCredentials));

            return new JsonResult(new { token });
        }


        [Authorize]
        [HttpGet("GetData")]
        public JsonResult GetData()
        {
            return new JsonResult(new { data = "Success" });
        }
    }
}

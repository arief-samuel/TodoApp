using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using TodoApp.Configuration;
using TodoApp.Dtos.Requests;
using TodoApp.Dtos.Responses;

namespace TodoApp.Controller
{
    [Route("api[controller]")]
    [ApiController]
    public class AuthManagementController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtConfig _jwtConfig;

        public AuthManagementController(
            UserManager<IdentityUser> userManager,
            IOptionsMonitor<JwtConfig> optionsMonitor)
        {
            _userManager = userManager;
            _jwtConfig = optionsMonitor.CurrentValue;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserLoginRequest user)
        {
            if (!ModelState.IsValid)
                return BadRequest(new RegistrationResponse()
                {
                    Result = false,
                    Errors = new List<string>(){
                                         "Invalid payload"
                                    }
                });

            var existingUser = await _userManager.FindByEmailAsync(user.Email);
            if (existingUser is null)
                return BadRequest(new RegistrationResponse()
                {
                    Result = false,
                    Errors = new List<string>(){
                        "Invalid authentication request"
                    }
                });

            // Now we need to check if the user has inputed the right password   
            var isCorrect = await _userManager.CheckPasswordAsync(existingUser, user.Password);
            if (!isCorrect)
                return BadRequest(new RegistrationResponse()
                {
                    Result = false,
                    Errors = new List<string>(){
                                         "Invalid authentication request"
                                    }
                });

            var jwtToken = GenerateJwtToken(existingUser);
            return Ok(new RegistrationResponse()
            {
                Result = true,
                Token = jwtToken
            });
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(
            [FromBody] UserRegistrationRequestDto user)
        {
            // Check if the incoming request is valid
            if (!ModelState.IsValid)
                return BadRequest(new RegistrationResponse()
                {
                    Result = false,
                    Errors = new List<string>(){
                        "Invalid Payload"
                    }
                });

            // check i the user with the same email exist
            var existingUser = await _userManager.FindByEmailAsync(user.Email);
            if (existingUser is not null)
                return BadRequest(new RegistrationResponse()
                {
                    Result = false,
                    Errors = new List<string>(){
                        "Email already exist"
                    }
                });

            var newUser = new IdentityUser() { Email = user.Email, UserName = user.Name };
            var isCreated = await _userManager.CreateAsync(newUser, user.Password);
            if (!isCreated.Succeeded)
                return new JsonResult(new RegistrationResponse()
                {
                    Result = false,
                    Errors = isCreated.Errors.Select(x => x.Description).ToList()
                })
                { StatusCode = 500 };

            var jwtToken = GenerateJwtToken(newUser);
            return Ok(new RegistrationResponse()
            {
                Result = true,
                Token = jwtToken
            });
        }

        private string GenerateJwtToken(IdentityUser user)
        {
            // Now its time to define the jwt token which will be responsible of creating our tokens
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            // We get our secret from the appsettings
            var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);

            // we define our token descriptor
            // We need to utilise claims which are properties in our token which gives information about the token
            // which belong to the specific user who it belongs to
            // so it could contain their id, name, email the good part is that these information
            // are generated by our server and identity framework which is valid and trusted
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]{
                    new Claim("Id", user.Id),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                    new Claim(JwtRegisteredClaimNames.Email,user.Email),
                    // the JTI is used for our refresh token which we will be convering in the next video
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                }),
                // the life span of the token needs to be shorter and utilise refresh token to keep the user signedin
                Expires = DateTime.Now.AddHours(6),
                // here we are adding the encryption alogorithim information which will be used to decrypt our token
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512Signature)
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);

            return jwtToken;
        }
    }
}
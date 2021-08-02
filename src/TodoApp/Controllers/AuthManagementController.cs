using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using TodoApp.Configuration;
using TodoApp.Data;
using TodoApp.Domain;
using TodoApp.Dtos.Requests;
using TodoApp.Dtos.Responses;
using TodoApp.Models;

namespace TodoApp.Controller
{
    [Route("api[controller]")]
    [ApiController]
    public class AuthManagementController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtConfig _jwtConfig;
        private readonly TokenValidationParameters _tokenValidationParameters;
        private readonly TodoAppDbContext _todoAppDbContext;

        public AuthManagementController(
            UserManager<IdentityUser> userManager,
            IOptionsMonitor<JwtConfig> optionsMonitor,
            TokenValidationParameters tokenValidationParameters,
            TodoAppDbContext todoAppDbContext)
        {
            _userManager = userManager;
            _jwtConfig = optionsMonitor.CurrentValue;
            _tokenValidationParameters = tokenValidationParameters;
            _todoAppDbContext = todoAppDbContext;
        }

        [HttpPost("refreshToken")]
        public async Task<IActionResult> RefreshToken(
            [FromBody] TokenRequest tokenRequest)
        {
            if (!ModelState.IsValid)
                return BadRequest(new RegistrationResponse()
                {
                    Errors = new List<string>(){
                        "Invalid Payload"
                    },
                    Success = false
                });

            var res = await VerifyToken(tokenRequest);

            if (res is null)
                return BadRequest(new RegistrationResponse()
                {
                    Errors = new List<string>(){
                        "Invalid Tokens"
                    },
                    Success = false
                });

            return Ok(res);
        }

        private async Task<AuthResult> VerifyToken(TokenRequest tokenRequest)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            try
            {
                // This validation function will make sure that the token meets the validation parameters
                // and its an actual jwt token not just a random string
                var principal = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParameters, out var validateToken);

                // Now we need to check if the token has a valid security algorithm
                if (validateToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);
                    if (result == false)
                    {
                        return null;
                    }
                }

                // Will get the time stamp in unix time
                var utcExpiryDate = long.Parse(principal.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);
                // we convert the expiry date from seconds to the date
                var expDate = UnixTimeStampToDateTime(utcExpiryDate);

                if (expDate > DateTime.Now)
                {
                    return new AuthResult()
                    {
                        Errors = new List<string>() {
                                "We can't refresh this since the token has not expired"
                            },
                        Success = false
                    };
                }

                // Check the token we got if its saved in the db
                var storedRefreshToken = await _todoAppDbContext.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);
                if (storedRefreshToken is null)
                {
                    return new AuthResult()
                    {
                        Errors = new List<string>() {
                            "refresh token doesnt exist"},
                        Success = false
                    };
                }

                // Check the date of the saved token if it has expired
                if (DateTime.Now > storedRefreshToken.ExpiryDate)
                {
                    return new AuthResult()
                    {
                        Errors = new List<string>{
                            " token has expired, user needs to relogin"
                        },
                        Success = false
                    };
                }

                // check if the refresh token has been used
                if (storedRefreshToken.IsUsed)
                {
                    return new AuthResult()
                    {
                        Errors = new List<string>{
                            " token has been used"
                        },
                        Success = false
                    };
                }

                // Check if the token is revoked
                if (storedRefreshToken.IsRevoked)
                {
                    return new AuthResult()
                    {
                        Errors = new List<string>{
                            " token has been revoked"
                        },
                        Success = false
                    };
                }
                // we are getting here the jwt token id
                var jti = principal.Claims.SingleOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
                // check the id that the recieved token has against the id saved in the db
                if (storedRefreshToken.JwtId != jti)
                {
                    return new AuthResult()
                    {
                        Errors = new List<string>{
                            " The token doesnt matched the saved token"
                        },
                        Success = false
                    };
                }

                storedRefreshToken.IsUsed = true;
                _todoAppDbContext.RefreshTokens.Update(storedRefreshToken);
                await _todoAppDbContext.SaveChangesAsync();

                var dbUser = await _userManager.FindByIdAsync(storedRefreshToken.UserId);
                return await GenerateJwtToken(dbUser);

            }
            catch (Exception ex)
            {
                if (ex.Message.Contains("Lifetime validation failed. The token is expired."))
                {

                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>() {
                            "Token has expired please re-login"
                        }
                    };

                }
                else
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>() {
                            "Something went wrong."
                        }
                    };
                }
                #region 
                // return new AuthResult()
                // {
                //     Errors = new List<string>{
                //             $"{ex.Message} + {ex.StackTrace}"
                //         },
                //     Success = false
                // };
                #endregion
            }
        }
        private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
        {
            // Unix timestamp is seconds past epoch
            var dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dtDateTime = dtDateTime.AddSeconds(unixTimeStamp).ToLocalTime();
            return dtDateTime;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(
            [FromBody] UserLoginRequest user)
        {
            if (!ModelState.IsValid)
                return BadRequest(new RegistrationResponse()
                {
                    Success = false,
                    Errors = new List<string>(){
                                         "Invalid payload"
                                    }
                });

            var existingUser = await _userManager.FindByEmailAsync(user.Email);
            if (existingUser is null)
                return BadRequest(new RegistrationResponse()
                {
                    Success = false,
                    Errors = new List<string>(){
                        "Invalid authentication request"
                    }
                });

            // Now we need to check if the user has inputed the right password   
            var isCorrect = await _userManager.CheckPasswordAsync(existingUser, user.Password);
            if (!isCorrect)
                return BadRequest(new RegistrationResponse()
                {
                    Success = false,
                    Errors = new List<string>(){
                                         "Invalid authentication request"
                                    }
                });

            return Ok(await GenerateJwtToken(existingUser));
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(
            [FromBody] UserRegistrationRequestDto user)
        {
            // Check if the incoming request is valid
            if (!ModelState.IsValid)
                return BadRequest(new RegistrationResponse()
                {
                    Success = false,
                    Errors = new List<string>(){
                        "Invalid Payload"
                    }
                });

            // check i the user with the same email exist
            var existingUser = await _userManager.FindByEmailAsync(user.Email);
            if (existingUser is not null)
                return BadRequest(new RegistrationResponse()
                {
                    Success = false,
                    Errors = new List<string>(){
                        "Email already exist"
                    }
                });

            var newUser = new IdentityUser() { Email = user.Email, UserName = user.Name };
            var isCreated = await _userManager.CreateAsync(newUser, user.Password);
            if (!isCreated.Succeeded)
                return new JsonResult(new RegistrationResponse()
                {
                    Success = false,
                    Errors = isCreated.Errors.Select(x => x.Description).ToList()
                })
                { StatusCode = 500 };

            return Ok(await GenerateJwtToken(newUser));
        }

        private async Task<AuthResult> GenerateJwtToken(IdentityUser user)
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
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                    // the JTI is used for our refresh token which we will be convering in the next video
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                }),
                // the life span of the token needs to be shorter and utilise refresh token to keep the user signedin
                Expires = DateTime.Now.AddSeconds(30),
                // here we are adding the encryption alogorithim information which will be used to decrypt our token
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);

            var refreshToken = new RefreshToken()
            {
                JwtId = token.Id,
                IsUsed = false,
                IsRevoked = false,
                UserId = user.Id,
                AddDate = DateTime.Now,
                ExpiryDate = DateTime.Now.AddMonths(6),
                Token = RandomString(35) + Guid.NewGuid()
            };

            await _todoAppDbContext.RefreshTokens.AddAsync(refreshToken);
            await _todoAppDbContext.SaveChangesAsync();

            return new AuthResult()
            {
                Token = jwtToken,
                Success = true,
                RefreshToken = refreshToken.Token
            };
        }
        private string RandomString(int length)
        {
            Random random = new();
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
            .Select(c => c[random.Next(c.Length)]).ToArray());
        }
    }
}
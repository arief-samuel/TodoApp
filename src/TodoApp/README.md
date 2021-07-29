As well download the source code:
https://github.com/arief-samuel/TodoApp/tree/Base

This is Part 2 of API dev series you can check the different parts by following the links:

Part 1: https://arief21.azurewebsites.net/asp-net-core-5-rest-api-step-by-step-2mb6
Part 3: https://arief21.azurewebsites.net/refresh-jwt-with-refresh-tokens-in-asp-net-core-5-rest-api-step-by-step-3en5
We will be basing our current work on our previous Todo REST API application that we have created in our last article (https://arief21.azurewebsites.net/asp-net-core-5-rest-api-step-by-step-2mb6).

You can follow along by either going through that article and building the application with me as we go or you can get the source code from github, https://github.com/arief-samuel/TodoApp/tree/.


Once we have our code ready lets get started.

The first thing we need to install some package to utilise authentication

```bash
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer 
dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore 
dotnet add package Microsoft.AspNetCore.Identity.UI 
```

lets see how our csproj look like :
```xml
<Project Sdk="Microsoft.NET.Sdk.Web">

  <PropertyGroup>
    <TargetFramework>net6.0</TargetFramework>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="5.0.8" />
    <PackageReference Include="Microsoft.AspNetCore.Identity.EntityFrameworkCore" Version="5.0.8" />
    <PackageReference Include="Microsoft.AspNetCore.Identity.UI" Version="5.0.8" />
    <PackageReference Include="Microsoft.EntityFrameworkCore.Sqlite" Version="5.0.8" />
    <PackageReference Include="Microsoft.EntityFrameworkCore.Tools" Version="5.0.8">
      <IncludeAssets>runtime; build; native; contentfiles; analyzers; buildtransitive</IncludeAssets>
      <PrivateAssets>all</PrivateAssets>
    </PackageReference>
    <PackageReference Include="Swashbuckle.AspNetCore" Version="5.6.3" />
  </ItemGroup>

</Project>
```

then we need to do is we need to update our appsettings.json, in our appsettings we will need to add a JWT settings section and within that settings we need to add a JWT secret

```json
"JwtConfig": {

    "Secret" : "thbwtkuaxtqjnrwqkewpqxyxjpyqaofw"
  },
```

In order for us to generate our secret we are going to use a free web tool to generate a random 32 char string https://www.browserling.com/tools/random-string

After adding the randomly generate 32 char string in our app settings now we need to create a new folder in our root directory called configuration.

Inside this configuration folder we will create a new class called JwtConfig

```csharp

public class JwtConfig
{
    public string Secret { get; set; }
}
```

Now we need to update our startup class, inside our ConfigureServices method we need to add the below in order to inject our JwtConfiguration in our application
```csharp
services.Configure<JwtConfig>(Configuration.GetSection("JwtConfig"));
```

Adding these configuration in our startup class register the configurations in our Asp.Net core middlewear and in our IOC container.

The next step is adding and configuring authentication in our startup class, inside our ConfigureServices method we need to add the following :
```csharp
// within this section we are configuring the authentication and setting the default scheme
 services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(jwt =>
            {
                var key = Encoding.ASCII.GetBytes(Configuration["JwtConfig:Secret"]);

                jwt.SaveToken = true;
                jwt.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,// this will validate the 3rd part of the jwt token using the secret that we added in the appsettings and verify we have generated the jwt token
                    IssuerSigningKey = new SymmetricSecurityKey(key), // Add the secret key to our Jwt encryption
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    RequireExpirationTime = false,
                    ValidateLifetime = true
                };
            });

            services.AddDefaultIdentity<IdentityUser>(options =>
                options.SignIn.RequireConfirmedAccount = true)
                    .AddEntityFrameworkStores<TodoAppDbContext>();
```

After updating the ConfigureServices we need to update the Configure method by adding authentication

```csharp
app.UseAuthentication();
```
Once we add the configurations we need to build the application to see if everything is still building as it should.

```bash
dotnet run
dotnet build
```

The next step is to update our TodoAppDbContext to take advantage of the Identity provider that Asp.Net provide for us, will navigate to our TodoAppDbContext in the Data folder and we update the ApiDbContext class as the following

```csharp
public class ApiDbContext : IdentityDbContext
```
by inheriting from IdentityDbContext instead of DbContext, EntityFramework will know that we are using authentication and it will build the infrastructure for us to utilise the default identity tables.

To Generate the identity tables in our database we need to prepare migrations scripts and run them. to do that inside the terminal we need to type the following
```bash
dotnet ef migrations add "Adding authentication to our Api"
dotnet ef database update
```
![migration](https://user-images.githubusercontent.com/63085636/127414701-be5f924c-dd1a-4866-9266-7f4447b52613.PNG)
Once our migrations is completed we can open our database app.db with SQLite studio and we can see that our identity tables has been created for us by Entity Framework
![sqlitestudio](https://user-images.githubusercontent.com/63085636/127414852-3399a8fa-ded8-42bc-a7e1-f50993efa54a.PNG)
The next step will be to setup our controllers and build the registration process for the user. Inside our controller folder will need to create a controller and our DTOs (data transfer objects).

Will start by adding a new folder called Domain in our root directory, and we add a class called AuthResult
```csharp
using System.Collections.Generic;

namespace TodoApp.Domain
{
    public class AuthResult
    {
        public string Token { get; set; }
        public bool Result { get; set; }
        public List<string> Errors { get; set; }
    }
}
```
Will start by adding some folders to organise our DTOs, inside the Models folder will add a folder called DTO and within the DTO folder will create 2 folders Requests/Responses

We need to add the UserRegistrationRequestDto which will be used by our registration action in the Controller. Then will navigate to Models/DTO/Requests and add a new class called UserRegistrationRequestDto

Models/Dto/Requests/UserRegistrationRequestDto.cs
// For simplicity we are only adding these 3 feilds we can change it and make it as complex as we need
```csharp
public class UserRegistrationRequestDto
{
    [Required]
    public string Name { get; set; }
    [Required]
    public string Email { get; set; }
    [Required]
    public string Password { get; set; }
}
```

Model/Dto/Response/RegistrationResponse.cs

```csharp
// We are inheriting from AuthResult class
public class RegistrationResponse : AuthResult
{

}
```
Now we need to add our user registration controller, inside our controller folder we add a new class we call it AuthManagementController and we update it with the code below
```csharp
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
```
Once we finish the registration action we can now test it in postman and get the jwt token

So the next step will be creating the user login request.
```csharp
public class UserLoginRequest
{
    [Required]
    public string Email { get; set; }
    [Required]
    public string Password { get; set; }
}
```

After that we need to add our login action in the AuthManagementControtller

```csharp
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
```

now we can test it out and we can see that our jwt tokens has been generated successfully, the next step is to secure our controller, to do that all we need to do is add the Authorise attribute to the controller
```csharp
[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
[Route("api/[controller]")] // api/todo
[ApiController]
public class TodoController : ControllerBase
```
And now if we test it we are not able to execute any request since we are not authorised, in order for us to send authorised requests we need to add the authorisation header with the bearer token so that Asp.Net can verify it and give us permission to execute the actions

Thank you for taking the time and reading the article

This is Part 2 of API dev series you can check the different parts by following the links:

Part 1: https://arief21.azurewebsites.net/2021/06/28/create-restful-web-api-using-net-6-and-sqlite-with-entity-framework

Part 3: https://arief21.azurewebsites.net/
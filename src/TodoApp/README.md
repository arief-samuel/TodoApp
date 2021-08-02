Hello friends, In this article I will be showing you today How to add refresh tokens to our JWT authentication to our Asp.Net Core REST API

Some of the topics we will cover are refresh tokens and New endpoints functionalities and utilising JWTs ("Json Web Tokens") and Bearer authentication.

You can also watch the full step by step video on YouTube:

As well download the source code:
https://github.com/mohamadlawand087/v8-refreshtokenswithJWT

This is Part 3 of API dev series you can check the different parts by following the links:

Part 1:https://asp-net-core-5-rest-api-step-by-step-2mb6
Part 2: https://asp-net-core-5-rest-api-authentication-with-jwt-step-by-step-140d


This is part 3 of our Rest API journey, and we will be basing our current work on our previous Todo REST API application that we have created in our last article, https:/asp-net-core-5-rest-api-authentication-with-jwt-step-by-step-140d. You can follow along by either going through the article and building the application with me as we go or you can get the source code from github.

Before we start implementing the Refresh Token functionality, let us examine how the refresh token logic will work.

By nature JWT tokens have an expiry time, the shorter the time the safer it is. there is 2 options to get new tokens after the JWT token has expired

Ask the user to login again, this is not a good user experience
Use refresh tokens to automatically re-authenticate the user and generate new JWT tokens.
So what is a refresh token, a refresh token can be anything from strings to Guids to any combination as long as its unique

Why is it important to have a short lived JWT token, if someone is stole our JWT token and started doing requests on the server, that token will only last for an amount of time before it expires and become useless. The only way to get a new token is using the refresh tokens or login in.

Another main point is what happens to all of the tokens that were generated based on an user credentials if the user changes their password. we don't want to invalidate all of the sessions. We can just update the refresh tokens so a new JWT token based on the new credentials will be generated.

As well a good way to implement automatic refresh tokens is before every request the client makes we need to check the expiry of the token if its expired we request a new one else we use the token we have to perform the request.

So in out application instead of just generating just a JWT token with every authorisation we will add a refresh token as well.

So lets get started, we will first start by updating our startup class, by making TokenValidationParameters available across the application by adding them to our Dependency Injection Container

remove jwt.SaveToken = true;
```csharp
jwt.SaveToken = true;
```

```csharp
var key = Encoding.ASCII.GetBytes(Configuration["JwtConfig:Secret"]);

var tokenValidationParameters = new TokenValidationParameters {
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(key),
    ValidateIssuer = false,
    ValidateAudience = false,
    ValidateLifetime = true,
    RequireExpirationTime = false,

    // Allow to use seconds for expiration of token
    // Required only when token lifetime less than 5 minutes
    // THIS ONE
    ClockSkew = TimeSpan.Zero
};

services.AddSingleton(tokenValidationParameters);

services.AddAuthentication(options => {
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(jwt => {
    jwt.SaveToken = true;
    jwt.TokenValidationParameters = tokenValidationParameters;
});
```
Once the JwtConfig class is updated now we need to update our GenerateJwtToken function in our AuthManagementController our TokenDescriptor Expire value from being fixed to the ExpiryTimeFrame, we need to make it shorter that we have specified

```csharp
private string GenerateJwtToken(IdentityUser user)
{
    var jwtTokenHandler = new JwtSecurityTokenHandler();

    var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);

    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new []
        {
            new Claim("Id", user.Id), 
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Sub, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        }),
        Expires = DateTime.UtcNow.AddSeconds(30),
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };

    var token = jwtTokenHandler.CreateToken(tokenDescriptor);
    var jwtToken = jwtTokenHandler.WriteToken(token);

    return jwtToken;
}
```

The step will be to update our AuthResult in our configuration folder, we need to add a new property which will be catered for the refresh token
```csharp
public class AuthResult
{
    public string Token { get; set; }
    public string RefreshToken { get; set; }
    public bool Success { get; set; }
    public List<string> Errors { get; set; }
}
```

We will add a new class called TokenRequest inside our Models/DTOs/Requests which will be responsible on accepting new request for the new endpoint that we will create later on to manage the refresh token
```csharp
public class TokenRequest
{
    [Required]
    public string Token { get; set; }
    [Required]
    public string RefreshToken { get; set; }
}
```

The next step is to create a new model called RefreshToken, in our Models folder.
```csharp
public class RefreshToken
{
    public int Id { get; set; }
    public string UserId { get; set; } // Linked to the AspNet Identity User Id
    public string Token { get; set; }
    public string JwtId { get; set; } // Map the token with jwtId
    public bool IsUsed { get; set; } // if its used we dont want generate a new Jwt token with the same refresh token
    public bool IsRevoked { get; set; } // if it has been revoke for security reasons
    public DateTime AddedDate { get; set; }
    public DateTime ExpiryDate { get; set; } // Refresh token is long lived it could last for months.

    [ForeignKey(nameof(UserId))]
    public IdentityUser User {get;set;}
}
```

Once the model is added we need to update our TodoAppDbContext
```c#
public virtual DbSet<RefreshToken> RefreshTokens {get;set;}
```
Now lets create the migrations for our TodoAppDbContext so we can reflect the changes in your database
```bash
dotnet ef migrations add "Added refresh tokens table"
dotnet ef database update
```
Our next step will be to create our new Endpoint "RefreshToken" in our AuthManagementController. The first thing we need to do is to inject the TokenValidationParameters

```csharp
private readonly TokenValidationParameters _tokenValidationParameters;
private readonly ApiDbContext _apiDbContext;

public AuthManagementController(
    UserManager<IdentityUser> userManager,
    IOptionsMonitor<JwtConfig> optionsMonitor,
    TokenValidationParameters tokenValidationParameters,
    ApiDbContext apiDbContext)
{
    _userManager = userManager;
    _jwtConfig = optionsMonitor.CurrentValue;
    _tokenValidationParameters = tokenValidationParameters;
    _apiDbContext = apiDbContext;
}
Once we inject the required parameters we need to update the GenerateToken function to include the refresh token
private async Task<AuthResult> GenerateJwtToken(IdentityUser user)
{
    var jwtTokenHandler = new JwtSecurityTokenHandler();

    var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);

    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new []
        {
            new Claim("Id", user.Id), 
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Sub, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        }),
        Expires = DateTime.UtcNow.Add(_jwtConfig.ExpiryTimeFrame),
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };

    var token = jwtTokenHandler.CreateToken(tokenDescriptor);
    var jwtToken = jwtTokenHandler.WriteToken(token);

    var refreshToken = new RefreshToken(){
        JwtId = token.Id,
        IsUsed = false,
        UserId = user.Id,
        AddedDate = DateTime.UtcNow,
        ExpiryDate = DateTime.UtcNow.AddYears(1),
        IsRevoked = false,
        Token = RandomString(25) + Guid.NewGuid()
    };

    await _apiDbContext.RefreshTokens.AddAsync(refreshToken);
    await _apiDbContext.SaveChangesAsync();

    return new AuthResult() {
        Token = jwtToken,
        Success = true,
        RefreshToken = refreshToken.Token
    };
}

public  string RandomString(int length)
{
    var random = new Random();
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    return new string(Enumerable.Repeat(chars, length)
    .Select(s => s[random.Next(s.Length)]).ToArray());
}
```
Now lets update the return to both existing actions as we have changed the return type for GenerateJwtToken

For Login Action:
```csharp
return Ok(await GenerateJwtToken(existingUser));
```

For Register Action:
```csharp
return Ok(await GenerateJwtToken(existingUser));
```

Now we can start building our RefreshToken Action

```csharp
[HttpPost]
[Route("RefreshToken")]
public async Task<IActionResult> RefreshToken([FromBody] TokenRequest tokenRequest)
{
    if(ModelState.IsValid)
    {
        var res = await VerifyToken(tokenRequest);

        if(res == null) {
                return BadRequest(new RegistrationResponse(){
                Errors = new List<string>() {
                    "Invalid tokens"
                },
                Success = false
            });
        }

        return Ok(res);
    }

    return BadRequest(new RegistrationResponse(){
            Errors = new List<string>() {
                "Invalid payload"
            },
            Success = false
    });
}
private async Task<AuthResult> VerifyToken(TokenRequest tokenRequest)
{
    var jwtTokenHandler = new JwtSecurityTokenHandler();

    try
    {
        // This validation function will make sure that the token meets the validation parameters
        // and its an actual jwt token not just a random string
        var principal = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParameters, out var validatedToken);

        // Now we need to check if the token has a valid security algorithm
        if(validatedToken is JwtSecurityToken jwtSecurityToken)
        {
            var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);

            if(result == false) {
                 return null;
            }
        }

                // Will get the time stamp in unix time
        var utcExpiryDate = long.Parse(principal.Claims.FirstOrDefaultAsync(x => x.Type == JwtRegisteredClaimNames.Exp).Value);

        // we convert the expiry date from seconds to the date
        var expDate = UnixTimeStampToDateTime(utcExpiryDate);

        if(expDate > DateTime.UtcNow)
        {
            return new AuthResult(){
                Errors = new List<string>() {"We cannot refresh this since the token has not expired"},
                Success = false
            };
        }

        // Check the token we got if its saved in the db
        var storedRefreshToken = await _apiDbContext.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken); 

        if(storedRefreshToken == null)
        {
            return new AuthResult(){
                Errors = new List<string>() {"refresh token doesnt exist"},
                Success = false
            };
        }

        // Check the date of the saved token if it has expired
        if(DateTime.UtcNow > storedRefreshToken.ExpiryDate)
        {
            return new AuthResult(){
                Errors = new List<string>() {"token has expired, user needs to relogin"},
                Success = false
            };
        }

        // check if the refresh token has been used
        if(storedRefreshToken.IsUsed)
        {
            return new AuthResult(){
                Errors = new List<string>() {"token has been used"},
                Success = false
            };
        }

        // Check if the token is revoked
        if(storedRefreshToken.IsRevoked)
        {
            return new AuthResult(){
                Errors = new List<string>() {"token has been revoked"},
                Success = false
            };
        }

         // we are getting here the jwt token id
        var jti = principal.Claims.SingleOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;

        // check the id that the recieved token has against the id saved in the db
        if(storedRefreshToken.JwtId != jti)
        {
           return new AuthResult(){
                Errors = new List<string>() {"the token doenst mateched the saved token"},
                Success = false
            };
        }

        storedRefreshToken.IsUsed = true;
        _apiDbContext.RefreshTokens.Update(storedRefreshToken);
        await _apiDbContext.SaveChangesAsync();

                var dbUser = await _userManager.FindByIdAsync(storedRefreshToken.UserId);
        return await GenerateJwtToken(dbUser);
    }
    catch(Exception ex)
    {
        return null;
    }
}

private DateTime UnixTimeStampToDateTime( double unixTimeStamp )
{
    // Unix timestamp is seconds past epoch
    System.DateTime dtDateTime = new DateTime(1970,1,1,0,0,0,0,System.DateTimeKind.Utc);
    dtDateTime = dtDateTime.AddSeconds( unixTimeStamp ). ToUniversalTime();
    return dtDateTime;
}

```
Finally we need to make sure everything still builds and run


```bash
dotnet build
dotnet run
```
Once we make sure everything is as it should be we will test the app using postman, the testing scenarios will be as follow:

login in generating a JWT token with a refresh token ⇒ fail
directly try to refresh the token without waiting for it to expire ⇒ fail
waiting for the JWT token to expire and request a refresh token ⇒ Success
re-using the same refresh token ⇒ fail
Thank you for taking the time and reading the article

This is Part 3 of API dev series you can check the different parts by following the links:

Part 1:https://asp-net-core-5-rest-api-step-by-step-2mb6
Part 2: https://asp-net-core-5-rest-api-authentication-with-jwt-step-by-step-140d

Thanks @grandsilence for your feedback the article has been updated
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using DotnetApiCompleteAuth.Constants;
using DotnetApiCompleteAuth.Models;
using DotnetApiCompleteAuth.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace DotnetApiCompleteAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountsController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogger<AccountsController> _logger;
        private readonly ITokenService _tokenService;

        public AccountsController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, ILogger<AccountsController> logger, ITokenService tokenService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _logger = logger;
            _tokenService = tokenService;
        }

        [HttpPost("signup")]
        public async Task<IActionResult> Signup(SignupModel model)
        {
            try
            {
                var existingUser = await _userManager.FindByNameAsync(model.Email);
                if (existingUser != null)
                {
                    return BadRequest("User already exists");
                }

                // Create User role if it doesn't exist
                if ((await _roleManager.RoleExistsAsync(Roles.User)) == false)
                {
                    var roleResult = await _roleManager
                          .CreateAsync(new IdentityRole(Roles.User));

                    if (roleResult.Succeeded == false)
                    {
                        var roleErros = roleResult.Errors.Select(e => e.Description);
                        _logger.LogError($"Failed to create user role. Errors : {string.Join(",", roleErros)}");
                        return BadRequest($"Failed to create user role. Errors : {string.Join(",", roleErros)}");
                    }
                }

                ApplicationUser user = new()
                {
                    Email = model.Email,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    UserName = model.Email,
                    Name = model.Name,
                    EmailConfirmed = true
                };

                // Attempt to create a user
                var createUserResult = await _userManager.CreateAsync(user, model.Password);

                // Validate user creation. If user is not created, log the error and
                // return the BadRequest along with the errors
                if (createUserResult.Succeeded == false)
                {
                    var errors = createUserResult.Errors.Select(e => e.Description);
                    _logger.LogError(
                        $"Failed to create user. Errors: {string.Join(", ", errors)}"
                    );
                    return BadRequest($"Failed to create user. Errors: {string.Join(", ", errors)}");
                }

                // adding role to user
                var addUserToRoleResult = await _userManager.AddToRoleAsync(user: user, role: Roles.User);

                if (addUserToRoleResult.Succeeded == false)
                {
                    var errors = addUserToRoleResult.Errors.Select(e => e.Description);
                    _logger.LogError($"Failed to add role to the user. Errors : {string.Join(",", errors)}");
                }
                return CreatedAtAction(nameof(Signup), null);
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }

        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginModel loginModel)
        {
            try
            {
                var user = await _userManager.FindByNameAsync(loginModel.Username);
                if (user == null ||
                !await _userManager.CheckPasswordAsync(user, loginModel.Password)
                )
                {
                    return Unauthorized();
                }

                // creating the necessary claims
                List<Claim> authClaims = [
                        new (ClaimTypes.Name, user.UserName),
                        new (JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                // unique id for token
        ];

                var userRoles = await _userManager.GetRolesAsync(user);

                // adding roles to the claims. So that we can get the user role from the token.
                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                // generating access token
                var token = _tokenService.GenerateAccessToken(authClaims);
                return Ok(token);
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }

    }
}

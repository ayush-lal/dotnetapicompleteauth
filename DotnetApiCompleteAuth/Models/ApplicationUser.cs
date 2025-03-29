using Microsoft.AspNetCore.Identity;

namespace DotnetApiCompleteAuth.Models;

public class ApplicationUser : IdentityUser
{
    public string Name { get; set; } = string.Empty;
}

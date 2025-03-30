using System.Security.Claims;

namespace DotnetApiCompleteAuth.Services;

public interface ITokenService
{
    string GenerateAccessToken(IEnumerable<Claim> claims);
}

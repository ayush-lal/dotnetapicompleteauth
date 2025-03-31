using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DotnetApiCompleteAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController()]
    [Authorize()]

    public class PeopleController : ControllerBase
    {
        [HttpGet]
        [AllowAnonymous]
        public IActionResult GetPeople()
        {
            return Ok("People data");
        }

        [HttpPost]
        public IActionResult CreatePerson()
        {
            return Ok("Person is created");
        }
    }
}

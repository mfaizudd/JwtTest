using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text;
using System.Security.Cryptography;
using JwtTest.Models;
using JwtTest.Data;
using JwtTest.Resources;
using System.Text.Json;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace JwtTest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {

        private JwtTestContext _context;
        private const string _privateKey = "SNeFPAsZ0V7FzDfm1oNhpPjFckk1tPmIymDyKh/hbY8=";

        public UsersController(JwtTestContext context)
        {
            _context = context;
        }

        // GET: api/Users
        [HttpGet]
        public IEnumerable<User> Get()
        {
            return _context.Users;
        }

        [HttpPost("Login")]
        public ActionResult Login([FromBody] LoginRequest loginRequest)
        {
            var username = loginRequest.Username;
            var password = loginRequest.Password;
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(password));
            var builder = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                builder.Append(bytes[i].ToString("x2"));
            }
            var passwordString = builder.ToString();
            var user = _context.Users.FirstOrDefault(x => x.Username == username && x.Password == passwordString);
            if (user == null) return NotFound();
            var payload = new
            {
                name = user.Name,
                exp = DateTime.UtcNow.AddMinutes(5),
                iat = DateTime.UtcNow
            };
            return Ok(JsonWebToken.Encode(payload, _privateKey));
        }

        // GET api/Users/5
        [HttpGet("{id}")]
        public User Get(int id)
        {
            return _context.Users.Find(id);
        }

        // POST api/Users
        [HttpPost]
        public ActionResult Post([FromBody] User request)
        {
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(request.Password));
            var builder = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                builder.Append(bytes[i].ToString("x2"));
            }
            var passwordString = builder.ToString();
            var user = new User()
            {
                Name = request.Name,
                Password = passwordString,
                Username = request.Username
            };
            _context.Users.Add(user);
            _context.SaveChanges();
            return Ok("Sukses");
        }

        // PUT api/Users/5
        [HttpPut("{id}")]
        public IActionResult Put(int id, [FromBody] User request)
        {
            var headers = Request.Headers;
            if (!headers.TryGetValue("Authorization", out var authHeaderString)) return Unauthorized();
            var authHeaders = authHeaderString.ToString().Split(' ');
            if (authHeaders.Length < 2 || authHeaders.Length > 2) return Unauthorized();
            if (authHeaders[0] != "Bearer") return Unauthorized();
            try
            {
                var payload = JsonWebToken.Decode(authHeaders[1], _privateKey);
                var jsonPayload = JsonDocument.Parse(payload).RootElement;
                var expire = jsonPayload.GetProperty("exp").GetDateTime();
                if (DateTime.UtcNow > expire)
                    return Unauthorized("yoken expired");
            }
            catch (ApplicationException)
            {
                return Unauthorized();
                throw;
            }

            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(request.Password));
            var builder = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                builder.Append(bytes[i].ToString("x2"));
            }
            var passwordString = builder.ToString();

            var user = _context.Users.FirstOrDefault(x => x.Id == id);
            user.Name = request.Name;
            user.Password = passwordString;
            user.Username = request.Username;

            _context.Users.Update(user);
            _context.SaveChanges();
            return Ok();
        }

        // DELETE api/Users/5
        [HttpDelete("{id}")]
        public IActionResult Delete(int id)
        {
            var user = _context.Users.Find(id);
            if (user == null)
                return NotFound();
            
            _context.Users.Remove(user);
            _context.SaveChanges();
            return Ok();
        }
    }
}

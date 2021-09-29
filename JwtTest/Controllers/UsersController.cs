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
            var hashedPassword = Encoding.ASCII.GetBytes(password);
            using var sha = SHA256.Create();
            hashedPassword = sha.ComputeHash(hashedPassword);
            var passwordString = Encoding.ASCII.GetString(hashedPassword);
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
                    return Unauthorized("Token expired");
            }
            catch (ApplicationException)
            {
                return Unauthorized();
                throw;
            }

            var password = Encoding.ASCII.GetBytes(request.Password);
            using (var sha = SHA256.Create())
            {
                password = sha.ComputeHash(password);
            }
            var user = new User()
            {
                Name = request.Name,
                Password = Encoding.ASCII.GetString(password),
                Username = request.Username
            };
            _context.Users.Add(user);
            _context.SaveChanges();
            return Ok();
        }

        // PUT api/Users/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] User request)
        {
            var password = Encoding.ASCII.GetBytes(request.Password);
            using (var sha = SHA256.Create())
            {
                password = sha.ComputeHash(password);
            }
            var user = new User()
            {
                Name = request.Name,
                Password = Encoding.ASCII.GetString(password),
                Username = request.Username
            };
            _context.Users.Update(user);
            _context.SaveChanges();
        }

        // DELETE api/Users/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
            var user = _context.Users.Find(id);
            _context.Users.Remove(user);
            _context.SaveChanges();
        }
    }
}

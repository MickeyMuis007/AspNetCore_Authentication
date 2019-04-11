using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AspNetCore.Auth.Web.Services
{
    public interface IUserService
    {
        Task<bool> ValidateCredentials(string username, string password, out User user);
    }

    public class User
    {
        public string Username { get; }
        public User(string username)
        {
            Username = username; 
        }
    }
}

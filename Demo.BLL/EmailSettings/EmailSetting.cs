
using Demo.DAL.Models.IdentityModule;
using Microsoft.Extensions.Configuration;
using System.Net;
using System.Net.Mail;

namespace Demo.BLL.EmailSettings
{
    public class EmailSetting(IConfiguration _configuration) : IEmailSetting
    {
        public void SendEmail(Email email)
        {
            var Client = new SmtpClient("smtp.gmail.com", 587);
            Client.EnableSsl = true;

            Client.Credentials = new NetworkCredential(_configuration["EmailAddress:Email"], _configuration["EmailAddress:Password"]);
            Client.Send(_configuration["EmailAddress:Email"]!, email.To, email.Subject, email.Body);
        }
    }
}

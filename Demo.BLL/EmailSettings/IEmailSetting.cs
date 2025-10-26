using Demo.DAL.Models.IdentityModule;

namespace Demo.BLL.EmailSettings
{
    public interface IEmailSetting
    {
        void SendEmail(Email email);
    }
}

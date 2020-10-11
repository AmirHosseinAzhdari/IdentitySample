using System.Threading.Tasks;

namespace IdentitySample.Repositories
{
    public interface IMessageSender
    {
        public Task SendEmailAsync(string toEmail, string subject, string message, bool messageHtml = false);
    }
}
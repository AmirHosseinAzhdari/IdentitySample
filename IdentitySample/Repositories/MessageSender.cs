﻿using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace IdentitySample.Repositories
{
    public class MessageSender : IMessageSender
    {
        public Task SendEmailAsync(string toEmail, string subject, string message, bool messageHtml = false)
        {
            using var client = new SmtpClient();
            var credentials = new NetworkCredential()
            {
                UserName = "amir.az3531", // without @gmail.com
                Password = "35313531"
            };

            client.Credentials = credentials;
            client.Host = "smtp.gmail.com";
            client.Port = 587;
            client.EnableSsl = true;

            using var emailMessage = new MailMessage()
            {
                To = { new MailAddress(toEmail) },
                From = new MailAddress("amir.az3531@gmail.com"), // with @gmail.com
                Subject = subject,
                Body = message,
                IsBodyHtml = messageHtml
            };

            client.Send(emailMessage);

            return Task.CompletedTask;
        }
    }
}
using Api.Data.Entities;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.AspNetCore.Identity;
using MimeKit;

namespace Api.Services;

public class EmailSenderService(IConfiguration configuration) : IEmailSender<User>
{
    private async Task SendEmailAsync(string toEmail, string subject, string message)
    {
        var smtpSettings = configuration.GetSection("SmtpSettings");

        var mailMessage = new MimeMessage();
        mailMessage.From.Add(new MailboxAddress(smtpSettings["SenderName"], smtpSettings["SenderEmail"]));
        mailMessage.To.Add(new MailboxAddress("", toEmail));
        mailMessage.Subject = subject;
        mailMessage.Body = new TextPart("html") { Text = message };

        using var smtpClient = new SmtpClient();

        try
        {
            await smtpClient.ConnectAsync(smtpSettings["Server"], int.Parse(smtpSettings["Port"]!), SecureSocketOptions.StartTls);

            await smtpClient.AuthenticateAsync(smtpSettings["Username"], smtpSettings["Password"]);

            await smtpClient.SendAsync(mailMessage);
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
        finally
        {
            await smtpClient.DisconnectAsync(true);
        }
    }
    
    public Task SendConfirmationLinkAsync(User user, string email, string confirmationLink)
    {
        var subject = "Confimação de e-mail - Intranet demo";
        var message = $"<p>Olá, {user.Name},</p>" +
                      "<p>Obrigado por se registrar no sistema Intranet demo. Por favor, clique no link abaixo para confirmar seu e-mail:</p>" +
                      $"<a href=\"{confirmationLink}\">Aqui</a>" +
                      "<p>Se você não se registrou, por favor ignore este e-mail.</p>" +
                      "<p>Atenciosamente.</p>";
        
        return SendEmailAsync(email, subject, message);
    }

    public Task SendPasswordResetLinkAsync(User user, string email, string resetLink)
    {
        string subject = "Reset de senha - Intranet demo";
        string message = $"<p>Olá, {user.Name},</p>" +
                         "<p>Recebemos uma solicitação para redefinir sua senha. Por favor, clique no link abaixo para redefinir sua senha:</p>" +
                         $"<a href=\"{resetLink}\">Aqui</a>" +
                         "<p>Se você não solicitou a redefinição de senha, por favor ignore este e-mail.</p>" +
                         "<p>Atenciosamente.</p>";

        return SendEmailAsync(email, subject, message);
    }

    public Task SendPasswordResetCodeAsync(User user, string email, string resetCode)
    {
        throw new NotImplementedException();
    }
}
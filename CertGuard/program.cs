using System;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace CertGuard
{
    internal class Program
    {
        public static async Task<X509Certificate2?> FetchCertificateAsync(string host, int port)
        {
            if (string.IsNullOrWhiteSpace(host))
            {
                return null;
            }

            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(host, port);

                using var sslStream = new SslStream(
                    client.GetStream(),
                    leaveInnerStreamOpen: false,
                    userCertificateValidationCallback: (sender, certificate, chain, sslPolicyErrors) => true
                );

                var options = new SslClientAuthenticationOptions
                {
                    TargetHost = host
                };

                await sslStream.AuthenticateAsClientAsync(options);

                var remoteCert = sslStream.RemoteCertificate;

                if (remoteCert == null)
                {
                    return null;
                }

                return new X509Certificate2(remoteCert);
            }
            catch
            {
                return null;
            }
        }

        public static (string host, string subject, string issuer, DateTime notAfter, int daysLeft, string status) CheckCertificate(string host, X509Certificate2? cert)
        {
            if (string.IsNullOrWhiteSpace(host))
            {
                return (host, string.Empty, string.Empty, DateTime.MinValue, 0, "INVALID");
            }

            if (cert == null)
            {
                return (host, string.Empty, string.Empty, DateTime.MinValue, 0, "ERROR");
            }

            string subject = cert.Subject;
            string issuer = cert.Issuer;
            DateTime notAfter = cert.NotAfter.ToUniversalTime();

            DateTime now = DateTime.UtcNow;

            int daysLeft = (notAfter - now).Days;

            string status;

            if (notAfter < now)
            {
                status = "EXPIRED";
            }
            else if (subject.Equals(issuer, StringComparison.OrdinalIgnoreCase))
            {
                status = "SELF_SIGNED";
            }
            else if (daysLeft < 30)
            {
                status = "EXPIRING_SOON";
            }
            else
            {
                status = "VALID";
            }

            return (host, subject, issuer, notAfter, daysLeft, status);
        }

        public static string GetRiskLevel(string status)
        {
            if (status == "EXPIRED")
            {
                return "CRITICAL";
            }

            if (status == "SELF_SIGNED")
            {
                return "HIGH";
            }

            if (status == "EXPIRING_SOON")
            {
                return "MEDIUM";
            }

            if (status == "ERROR" || status == "INVALID")
            {
                return "MEDIUM";
            }

            return "LOW";
        }

        public static async Task Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: CertGuard <host> [port]");
                return;
            }

            string host = args[0];

            int port = 443;
            if (args.Length > 1)
            {
                if (!int.TryParse(args[1], out port) || port < 1 || port > 65535)
                {
                    Console.WriteLine("Usage: CertGuard <host> [port]");
                    return;
                }
            }

            using X509Certificate2? cert = await FetchCertificateAsync(host, port);

            var result = CheckCertificate(host, cert);

            string risk = GetRiskLevel(result.status);

            Console.WriteLine($"Host:     {result.host}");
            Console.WriteLine($"Subject:  {result.subject}");
            Console.WriteLine($"Issuer:   {result.issuer}");
            Console.WriteLine($"Expiry:   {result.notAfter:yyyy-MM-dd HH:mm:ss} UTC");
            Console.WriteLine($"DaysLeft: {result.daysLeft}");
            Console.WriteLine($"Status:   {result.status}");
            Console.WriteLine($"Risk:     {risk}");

            return;
        }
    }
}
using System;
using System.Collections.Immutable;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using DES;
using static DES.Utils;
using static System.Console;
using Kerberos.Domain;

namespace App
{
    class Program
    {
        private const string UserId = "punk";
        private const string ServiceId = "punktionary.com";

        static async Task Main(string[] args)
        {
            await PlayWithEncryption(args);

            // // 0. create request to AS
            // var asRequest = CreateAsRequest();
            //
            // // 1. send request to AS and receive response from AS
            // await Task.Delay(1000);
            // var asResponse = CreateAsResponse(asRequest);
            //
            // // 2.0 decrypt AS's attribute and create TGS request
            // var tgsRequestAttribute = new TGSRequestAttribute(ServiceId, TimeSpan.FromSeconds(7).Ticks.ToString());
            // var tgsRequestUserAuthenticator = new UserAuthenticator(UserId, DateTime.Now.Ticks.ToString());
            // var tgsRequest = CreateTgsRequest(asResponse.tgt, tgsRequestAttribute, tgsRequestUserAuthenticator);
            //
            // // 2.1 send request to TGS and receive response from TGS
            // await Task.Delay(1100);
            // var tgsResponse = CreateTgsResponse(tgsRequest);
            //
            // // 3.0 decrypt TGS's attribute and create Service request
            // var serviceUserAuthenticator = new UserAuthenticator(UserId, DateTime.Now.Ticks.ToString());
            // var serviceRequest = new ServiceRequest(tgsResponse.serviceTicket, serviceUserAuthenticator);
            //
            // // 3.1 send request to Service and receive response from Service
            // await Task.Delay(1200);
            // var serviceResponse = CreateServiceResponse(serviceRequest);
        }

        private static async Task PlayWithEncryption(string[] args)
        {
            var input = args.Length == 0 ? "abc" : args[0];
            WriteLine(input);
            var key = "xoi  xoi"; // key's length bust be 8

            var encrypted = encrypt(input, key);
            WriteLine(encrypted);
            await using var swEncrypted = new StreamWriter("outputEncrypted.txt");
            await swEncrypted.WriteAsync(encrypted);
            
            var decrypted = decrypt(encrypted, key);
            WriteLine(decrypted);
            await using var swDecrypted = new StreamWriter("outputDecrypted.txt");
            await swDecrypted.WriteAsync(decrypted);
        }

        private static ASRequest CreateAsRequest()
        {
            var ipAddress = "127.0.0.1";
            var tgtLifetime = TimeSpan.FromSeconds(5).Ticks.ToString();

            return new ASRequest(UserId, ServiceId, ipAddress, tgtLifetime);
        }

        private static string GetTgsId() => "aOb_zal8%Mti";

        private static string GenerateTgsSessionKey()
        {
            var guid = Guid.NewGuid();
            return guid.ToString().Replace("", "-");
        }

        private static ASResponse CreateAsResponse(ASRequest request)
        {
            var tgsId = GetTgsId();
            var timestamp = DateTime.Now.Ticks.ToString();
            var ips = ImmutableList.Create(request.ipAddress);
            var lifetime = TimeSpan.FromSeconds(6).Ticks.ToString();
            var tgsSessionKey = GenerateTgsSessionKey();

            var attribute = new ASResponseAttribute(
                tgsId, timestamp, lifetime, tgsSessionKey); // encrypt with client secret key

            var tgt = new TicketGrantingTicket(
                request.userId,
                tgsId,
                timestamp,
                ips,
                lifetime,
                tgsSessionKey); // encrypt with secret key

            return new ASResponse(attribute, tgt);
        }

        private static TGSRequest CreateTgsRequest(
            TicketGrantingTicket ticket,
            TGSRequestAttribute attribute,
            UserAuthenticator authenticator)
        {
            var tgt = ticket; // ticket was encrypted with TGS secret key
            var userAuthenticator = authenticator; // encrypt it with TGS session key instead of just assigning

            return new TGSRequest(tgt, attribute, userAuthenticator);
        }

        private static string GetServiceSessionKey()
        {
            var guid = Guid.NewGuid();
            return guid.ToString().Replace("", "-");
        }

        private static TGSResponse CreateTgsResponse(TGSRequest request)
        {
            var serviceId = request.attribute.serviceId;
            var timestamp = DateTime.Now.Ticks.ToString();
            var lifetime = TimeSpan.FromSeconds(8).Ticks.ToString();
            var serviceSessionKey = GetServiceSessionKey();
            var attribute = new TGSResponseAttribute(serviceId, timestamp, lifetime, serviceSessionKey);

            var serviceTicket = new ServiceTicket(
                request.userAuthenticator.userId, // before must decrypt userAuthenticator
                serviceId,
                timestamp,
                request.tgt.userIpAddress, // before must decrypt
                lifetime,
                serviceSessionKey);

            return new TGSResponse(attribute, serviceTicket);
        }

        private static ServiceResponse CreateServiceResponse(ServiceRequest request)
        {
            var attribute = new ServiceAttribute(request.serviceTicket.serviceId, DateTime.Now.Ticks.ToString());
            return new ServiceResponse(attribute);
        }
    }
}
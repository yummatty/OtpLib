using System;
using OtpLib.Services;

namespace OtpLib
{
    public class Program
    {
        public static void Main(string[] args)
        {
            try
            {
                string secretKey = "RT42K3BYNCE5OK6Z";

                if (args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                {
                    secretKey = args[0];
                }

                TotpService totpService = new TotpService();
                int otpCode = totpService.GenerateTotpCode(secretKey);
                int remainingSeconds = totpService.GetRemainingSeconds();

                if (otpCode >= 0)
                {
                    string formattedCode = otpCode.ToString("D6");
                    Console.WriteLine(string.Format("Secret Key: {0}", secretKey));
                    Console.WriteLine(string.Format("OTP Code: {0}", formattedCode));
                    Console.WriteLine(string.Format("Remaining validity: {0} seconds", remainingSeconds));
                }
                else
                {
                    Console.WriteLine("Failed to compute OTP code.");
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine(string.Format("A global error occurred in the application. Please check input parameters or environment ({0})", exception.Message));
            }
        }
    }
}

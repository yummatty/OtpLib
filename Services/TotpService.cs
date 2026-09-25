using System;
using System.IO;
using System.Security.Cryptography;

namespace OtpLib.Services
{
    public class TotpService
    {
        private byte[] DecodeBase32(string secret)
        {
            if (string.IsNullOrWhiteSpace(secret))
            {
                throw new ArgumentException("The secret cannot be null or whitespace.", nameof(secret));
            }

            string cleanSecret = secret.Trim().ToUpperInvariant().Replace(" ", "").Replace("=", "");
            int byteCount = cleanSecret.Length * 5 / 8;
            byte[] resultBytes = new byte[byteCount];
            int buffer = 0;
            int bitCount = 0;
            int writeIndex = 0;

            for (int index = 0; index < cleanSecret.Length; index = index + 1)
            {
                char character = cleanSecret[index];
                int characterValue = -1;

                if (character >= 'A' && character <= 'Z')
                {
                    characterValue = character - 'A';
                }
                else if (character >= '2' && character <= '7')
                {
                    characterValue = character - '2' + 26;
                }
                else
                {
                    throw new FormatException(string.Format("Invalid Base32 character detected: {0}", character));
                }

                buffer = (buffer << 5) | characterValue;
                bitCount = bitCount + 5;

                if (bitCount >= 8)
                {
                    bitCount = bitCount - 8;
                    if (writeIndex < resultBytes.Length)
                    {
                        resultBytes[writeIndex] = (byte)((buffer >> bitCount) & 0xFF);
                        writeIndex = writeIndex + 1;
                    }
                }
            }

            return resultBytes;
        }

        public int GenerateTotpCode(string secretKey)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(secretKey))
                {
                    throw new ArgumentException("The secret key cannot be null or empty.", nameof(secretKey));
                }

                long unixEpochSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                long timeStepNumber = unixEpochSeconds / 30L;

                byte[] keyBytes = this.DecodeBase32(secretKey);
                byte[] counterBytes = BitConverter.GetBytes(timeStepNumber);

                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(counterBytes);
                }

                using (HMACSHA1 hmac = new HMACSHA1(keyBytes))
                {
                    byte[] hashBytes = hmac.ComputeHash(counterBytes);
                    int offset = hashBytes[hashBytes.Length - 1] & 0x0F;

                    int binaryCode = ((hashBytes[offset] & 0x7F) << 24)
                                   | ((hashBytes[offset + 1] & 0xFF) << 16)
                                   | ((hashBytes[offset + 2] & 0xFF) << 8)
                                   | (hashBytes[offset + 3] & 0xFF);

                    int totpCode = binaryCode % 1000000;
                    return totpCode;
                }
            }
            catch (ArgumentException exception)
            {
                Console.WriteLine(string.Format("Please provide a valid 2FA secret key. Parameter validation is recommended ({0})", exception.Message));
                return -1;
            }
            catch (FormatException exception)
            {
                Console.WriteLine(string.Format("The 2FA secret key is not a valid Base32 encoding. Please check input characters ({0})", exception.Message));
                return -1;
            }
            catch (Exception exception)
            {
                Console.WriteLine(string.Format("An unexpected error occurred during OTP code generation. Please try again ({0})", exception.Message));
                return -1;
            }
        }

        public int GetRemainingSeconds()
        {
            long unixEpochSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            int elapsedSeconds = (int)(unixEpochSeconds % 30L);
            int remainingSeconds = 30 - elapsedSeconds;
            return remainingSeconds;
        }
    }
}

using System;
using System.IO;
using System.Security.Cryptography;

namespace Aura.Common.Services
{
    public static class HashService
    {
        public static string CalculateSHA256(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("Doğrulanacak dosya bulunamadı.", filePath);

            using (var sha256 = SHA256.Create())
            {
                using (var stream = File.OpenRead(filePath))
                {
                    var hashBytes = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                }
            }
        }
    }
}
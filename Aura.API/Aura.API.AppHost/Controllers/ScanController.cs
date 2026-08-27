using Microsoft.AspNetCore.Mvc;
using Aura.Common.Models;
using System.Linq;

namespace Aura.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ScanController : ControllerBase
    {
        [HttpPost("submit")]
        public IActionResult SubmitScan([FromBody] ScanResultDto result)
        {
            if (result == null || string.IsNullOrEmpty(result.LicenseKey))
            {
                return BadRequest(new { Message = "Geçersiz tarama verisi veya lisans anahtarı." });
            }

            // Taranan dosyalarda uyumsuzluk/şüpheli dosya var mı kontrolü
            bool hasSuspiciousFiles = result.CheckedFiles.Any(f => !f.IsMatched);
            result.IsValid = !hasSuspiciousFiles;

            // Şüpheli/değiştirilmiş dosyaları tespit edelim
            var suspiciousFiles = result.CheckedFiles.Where(f => !f.IsMatched).ToList();

            // LOG / BİLGİLENDİRME (İleride burası PostgreSQL veritabanına kaydedilecek)
            System.Console.WriteLine($"[TARAMA GELDI] Oyuncu: {result.PlayerName} | Lisans: {result.LicenseKey}");
            System.Console.WriteLine($"[DURUM] Total Dosya: {result.CheckedFiles.Count} | Şüpheli Dosya: {suspiciousFiles.Count}");

            return Ok(new
            {
                Message = "Tarama raporu sunucuya başarıyla ulaştı.",
                Status = result.IsValid ? "Temiz" : "Şüpheli Dosya Tespit Edildi!",
                TotalFiles = result.CheckedFiles.Count,
                SuspiciousCount = suspiciousFiles.Count
            });
        }
    }
}
using System;
using System.Collections.Generic;

namespace Aura.Common.Models
{
    public class ScanResultDto
    {
        public string LicenseKey { get; set; }
        public string PlayerName { get; set; }
        public DateTime ScanTime { get; set; } = DateTime.UtcNow;
        public List<FileCheckItem> CheckedFiles { get; set; } = new List<FileCheckItem>();
        public bool IsValid { get; set; }
    }

    public class FileCheckItem
    {
        public string FilePath { get; set; }
        public string Hash { get; set; }
        public bool IsMatched { get; set; }
    }
}
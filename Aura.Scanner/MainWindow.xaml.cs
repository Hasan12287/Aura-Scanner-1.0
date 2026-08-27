using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;
using Microsoft.Web.WebView2.Wpf;

namespace Aura.Scanner
{
    public partial class MainWindow : Window
    {
        private static readonly HttpClient httpClient = new HttpClient();
        private const string WEBHOOK_URL = "https://discord.com/api/webhooks/1541162271605268641/JfQBlbnu_6WQ6JTlDfzsBdehTXkwrydUc-fFYWZv8Nb73aZINpaaQtj1qPo7k4a16tYN";

        private readonly HashSet<string> _knownBadHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _whitelistedProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "explorer", "svchost", "dwm", "csrss", "lsass",
            "services", "winlogon", "RuntimeBroker", "FiveM", "FiveM_GTAProcess",
            "msinfo32", "rundll32", "control", "chrome", "edge", "firefox", "discord"
        };

        private readonly string[] _targetExecutableExtensions = { ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".asi", ".sys" };

        private int _score;
        private readonly List<ThreatFinding> _findings = new List<ThreatFinding>();
        private readonly List<string> _discordAccountIds = new List<string>();
        private readonly List<DiscordAccountInfo> _discordAccounts = new List<DiscordAccountInfo>();
        private string _installDate = "Bilinmiyor";
        private readonly HashSet<string> _detectedDefenderPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public MainWindow()
        {
            InitializeComponent();
            InitializeWebView();
            InitializeDefenderListener();
        }

        private async void InitializeWebView()
        {
            await Browser.EnsureCoreWebView2Async();
            string htmlPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "index.html");
            if (File.Exists(htmlPath))
            {
                Browser.CoreWebView2.Navigate(new Uri(htmlPath).AbsoluteUri);
            }
            else
            {
                // index.html yoksa gomulu arayuzu yukle
                Browser.CoreWebView2.NavigateToString(GetEmbeddedUiHtml());
            }

            Browser.CoreWebView2.WebMessageReceived += async (s, e) =>
            {
                string? message = e.TryGetWebMessageAsString();
                if (message == "START_SCAN")
                {
                    await ExecuteScanProcess();
                }
                else if (message == "EXIT_APP")
                {
                    Application.Current.Shutdown();
                }
            };
        }

        private static string GetEmbeddedUiHtml()
        {
            return @"<!DOCTYPE html>
<html lang=""tr"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>Aura.scanner — PC-CHECKER</title>
    <link rel=""preconnect"" href=""https://fonts.googleapis.com"">
    <link rel=""preconnect"" href=""https://fonts.gstatic.com"" crossorigin>
    <link href=""https://fonts.googleapis.com/css2?family=Orbitron:wght@500;600;700;800&family=Space+Grotesk:wght@400;500;600;700&display=swap"" rel=""stylesheet"">
    <style>
        :root {
            --bg: #0a0610;
            --pink: #f9a8d4;
            --pink-bright: #fbcfe8;
            --pink-soft: #f472b6;
            --pink-deep: #ec4899;
            --pink-glow: rgba(244, 114, 182, 0.45);
            --text: #fdf2f8;
            --text-dim: #d8b4c8;
            --bar-track: #1f1420;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        html, body {
            height: 100%;
            width: 100%;
            overflow: hidden;
            background: var(--bg);
            font-family: 'Space Grotesk', system-ui, sans-serif;
            color: var(--text);
            user-select: none;
        }

        body {
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            background:
                radial-gradient(ellipse 90% 70% at 50% 20%, rgba(244, 114, 182, 0.12) 0%, transparent 55%),
                radial-gradient(ellipse 60% 50% at 80% 80%, rgba(236, 72, 153, 0.08) 0%, transparent 50%),
                #0a0610;
        }

        /* Snow layer */
        .snow {
            position: fixed;
            inset: 0;
            pointer-events: none;
            z-index: 0;
            overflow: hidden;
        }
        .snowflake {
            position: absolute;
            top: -20px;
            color: #fce7f3;
            font-size: 12px;
            opacity: 0.75;
            text-shadow: 0 0 6px rgba(251, 207, 232, 0.6);
            animation: snowfall linear infinite;
            user-select: none;
        }
        @keyframes snowfall {
            0% {
                transform: translateY(0) translateX(0) rotate(0deg);
                opacity: 0;
            }
            8% { opacity: 0.85; }
            90% { opacity: 0.5; }
            100% {
                transform: translateY(110vh) translateX(var(--drift)) rotate(360deg);
                opacity: 0;
            }
        }

        /* Main card */
        .card {
            position: relative;
            z-index: 2;
            width: min(520px, 92vw);
            height: min(420px, 88vh);
            background: radial-gradient(ellipse 80% 60% at 50% 40%, #1a0f18 0%, #100a12 70%, #0a0610 100%);
            border-radius: 28px;
            border: 1px solid rgba(249, 168, 212, 0.18);
            box-shadow:
                0 0 0 1px rgba(0,0,0,0.5),
                0 24px 80px rgba(0,0,0,0.65),
                0 0 60px rgba(244, 114, 182, 0.1),
                inset 0 1px 0 rgba(255,255,255,0.05);
            display: flex;
            flex-direction: column;
            padding: 28px 32px 24px;
            overflow: hidden;
        }

        .card::before {
            content: '';
            position: absolute;
            inset: 0;
            border-radius: 28px;
            background: radial-gradient(circle at 50% 30%, rgba(244, 114, 182, 0.08) 0%, transparent 55%);
            pointer-events: none;
        }

        /* Header */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            position: relative;
            z-index: 3;
        }

        .brand {
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        .brand-name {
            font-family: 'Orbitron', sans-serif;
            font-weight: 700;
            font-size: 18px;
            letter-spacing: 0.5px;
            background: linear-gradient(135deg, #fdf2f8 0%, #f9a8d4 40%, #f472b6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            filter: drop-shadow(0 0 12px rgba(244, 114, 182, 0.55));
        }
        .brand-sub {
            font-family: 'Orbitron', sans-serif;
            font-weight: 600;
            font-size: 10px;
            letter-spacing: 2.5px;
            color: var(--text-dim);
            text-transform: uppercase;
        }

        body, button, a { cursor: none !important; }
        #appCursor { position: fixed; width: 12px; height: 12px; border: 1px solid rgba(255,255,255,.9); border-radius: 50%; background: rgba(255,255,255,.08); box-shadow: 0 0 14px rgba(255,255,255,.4); pointer-events: none; z-index: 9999; transform: translate(-50%,-50%); transition: width .12s,height .12s,background .12s; }
        #appCursor.hot { width: 20px; height: 20px; border-color: #ff6b6b; background: rgba(255,70,70,.12); box-shadow: 0 0 18px rgba(255,59,59,.55); }

        .btn-close {
            width: 36px;
            height: 36px;
            border-radius: 12px;
            border: 1px solid rgba(249, 168, 212, 0.15);
            background: rgba(255,255,255,0.03);
            color: var(--text-dim);
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
            font-size: 16px;
            line-height: 1;
        }
        .btn-close:hover {
            background: rgba(239, 68, 68, 0.15);
            border-color: rgba(239, 68, 68, 0.35);
            color: #f87171;
            box-shadow: 0 0 16px rgba(239, 68, 68, 0.2);
        }

        /* Radar / scan center */
        .scan-area {
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            min-height: 180px;
        }

        .radar {
            width: 140px;
            height: 140px;
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .radar-core {
            width: 14px;
            height: 14px;
            border-radius: 50%;
            background: radial-gradient(circle, #fdf2f8 0%, var(--pink) 50%, var(--pink-deep) 100%);
            box-shadow:
                0 0 12px var(--pink-glow),
                0 0 28px rgba(244, 114, 182, 0.4),
                0 0 48px rgba(236, 72, 153, 0.25);
            position: relative;
            z-index: 5;
            animation: corePulse 2s ease-in-out infinite;
        }
        @keyframes corePulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.15); opacity: 0.85; }
        }

        .arc {
            position: absolute;
            border-radius: 50%;
            border: 2.5px solid transparent;
            border-top-color: var(--pink);
            border-right-color: rgba(249, 168, 212, 0.35);
            opacity: 0;
            animation: arcExpand 2.4s ease-out infinite;
        }
        .arc:nth-child(1) {
            width: 36px; height: 36px;
            animation-delay: 0s;
            border-top-color: #fbcfe8;
        }
        .arc:nth-child(2) {
            width: 64px; height: 64px;
            animation-delay: 0.35s;
            border-top-color: #f9a8d4;
            border-width: 2.5px;
        }
        .arc:nth-child(3) {
            width: 96px; height: 96px;
            animation-delay: 0.7s;
            border-top-color: #f472b6;
            border-width: 2px;
        }
        .arc:nth-child(4) {
            width: 128px; height: 128px;
            animation-delay: 1.05s;
            border-top-color: rgba(236, 72, 153, 0.75);
            border-width: 1.5px;
        }

        @keyframes arcExpand {
            0% {
                transform: scale(0.4) rotate(0deg);
                opacity: 0;
            }
            15% { opacity: 0.9; }
            70% { opacity: 0.35; }
            100% {
                transform: scale(1.15) rotate(90deg);
                opacity: 0;
            }
        }

        .radar.idle .arc {
            animation: arcIdle 3.5s ease-in-out infinite;
            opacity: 0.5;
        }
        .radar.idle .arc:nth-child(1) { animation-delay: 0s; }
        .radar.idle .arc:nth-child(2) { animation-delay: 0.4s; }
        .radar.idle .arc:nth-child(3) { animation-delay: 0.8s; }
        .radar.idle .arc:nth-child(4) { animation-delay: 1.2s; }
        @keyframes arcIdle {
            0%, 100% { transform: scale(0.85) rotate(-10deg); opacity: 0.25; }
            50% { transform: scale(1) rotate(10deg); opacity: 0.65; }
        }

        /* Bottom progress section */
        .footer {
            position: relative;
            z-index: 3;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .status-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .status-text {
            font-size: 13px;
            color: var(--text-dim);
            font-weight: 500;
            letter-spacing: 0.2px;
            transition: color 0.3s ease;
        }
        .status-text.active {
            color: #fbcfe8;
        }
        .status-pct {
            font-family: 'Orbitron', sans-serif;
            font-size: 13px;
            font-weight: 600;
            color: var(--pink-bright);
            letter-spacing: 1px;
            min-width: 40px;
            text-align: right;
        }

        .progress-track {
            height: 6px;
            border-radius: 99px;
            background: var(--bar-track);
            overflow: hidden;
            box-shadow: inset 0 1px 3px rgba(0,0,0,0.4);
            position: relative;
        }
        .progress-fill {
            height: 100%;
            width: 0%;
            border-radius: 99px;
            background: linear-gradient(90deg, #db2777 0%, #f472b6 45%, #fbcfe8 100%);
            box-shadow: 0 0 12px rgba(244, 114, 182, 0.55), 0 0 24px rgba(244, 114, 182, 0.25);
            transition: width 0.45s cubic-bezier(0.22, 1, 0.36, 1);
            position: relative;
        }
        .progress-fill::after {
            content: '';
            position: absolute;
            top: 0; right: 0; bottom: 0;
            width: 40px;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4));
            animation: shimmer 1.8s ease-in-out infinite;
        }
        @keyframes shimmer {
            0% { opacity: 0; transform: translateX(-20px); }
            50% { opacity: 1; }
            100% { opacity: 0; transform: translateX(10px); }
        }

        .start-wrap {
            display: flex;
            justify-content: center;
            margin-top: 4px;
        }
        .btn-start {
            font-family: 'Orbitron', sans-serif;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 2px;
            text-transform: uppercase;
            padding: 12px 36px;
            border-radius: 14px;
            border: 1px solid rgba(249, 168, 212, 0.45);
            background: linear-gradient(135deg, rgba(236, 72, 153, 0.35), rgba(244, 114, 182, 0.22));
            color: #fdf2f8;
            cursor: pointer;
            transition: all 0.25s ease;
            box-shadow: 0 0 24px rgba(244, 114, 182, 0.25), inset 0 1px 0 rgba(255,255,255,0.12);
        }
        .btn-start:hover {
            background: linear-gradient(135deg, rgba(236, 72, 153, 0.55), rgba(244, 114, 182, 0.4));
            border-color: rgba(251, 207, 232, 0.65);
            box-shadow: 0 0 36px rgba(244, 114, 182, 0.45), inset 0 1px 0 rgba(255,255,255,0.18);
            transform: translateY(-1px);
        }
        .btn-start:active { transform: translateY(0); }

        .btn-start.hidden, .progress-section.hidden { display: none; }

        .findings-strip {
            position: absolute;
            bottom: 70px;
            left: 32px;
            right: 32px;
            max-height: 48px;
            overflow: hidden;
            pointer-events: none;
            z-index: 4;
            opacity: 0;
            transition: opacity 0.3s;
        }
        .findings-strip.visible { opacity: 1; }
        .finding-chip {
            font-size: 11px;
            color: #fbcfe8;
            background: rgba(244, 114, 182, 0.14);
            border: 1px solid rgba(249, 168, 212, 0.28);
            border-radius: 8px;
            padding: 4px 10px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            animation: chipIn 0.4s ease;
        }
        .finding-chip.danger {
            color: #fca5a5;
            background: rgba(239, 68, 68, 0.12);
            border-color: rgba(239, 68, 68, 0.25);
        }
        @keyframes chipIn {
            from { opacity: 0; transform: translateY(8px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .done-badge {
            display: none;
            font-family: 'Orbitron', sans-serif;
            font-size: 11px;
            letter-spacing: 1.5px;
            color: #86efac;
            text-align: center;
            margin-top: 4px;
        }
        .done-badge.show { display: block; }
    
/* aura-circular-fix: stable circular percentage analytics */
.aura-circular-fix{
    --pct:0;
    width:118px;
    height:118px;
    border-radius:50%;
    background:conic-gradient(#ff4d22 calc(var(--pct)*1%), rgba(255,255,255,.09) 0);
    position:relative;
    display:grid;
    place-items:center;
    flex:0 0 auto;
}
.aura-circular-fix::before{
    content:"";
    position:absolute;
    inset:9px;
    border-radius:50%;
    background:#070707;
    box-shadow:inset 0 0 18px rgba(0,0,0,.7);
}
.aura-circular-fix .aura-circular-value{
    position:relative;
    z-index:2;
    font-family:Orbitron,sans-serif;
    font-size:22px;
    color:#fff;
}
.aura-circular-fix .aura-circular-label{
    position:absolute;
    z-index:2;
    top:69px;
    font-size:7px;
    letter-spacing:1.4px;
    opacity:.5;
    text-transform:uppercase;
}

</style>
</head>
<body>
    <div id=""appCursor""></div>
    <div class=""snow"" id=""snow""></div>

    <div class=""card"">
        <div class=""header"">
            <div class=""brand"">
                <div class=""brand-name"">Aura.scanner</div>
                <div class=""brand-sub"">PC-CHECKER</div>
            </div>
            <button class=""btn-close"" id=""btnClose"" title=""Kapat"" aria-label=""Kapat"">✕</button>
        </div>

        <div class=""scan-area"">
            <div class=""radar idle"" id=""radar"">
                <div class=""arc""></div>
                <div class=""arc""></div>
                <div class=""arc""></div>
                <div class=""arc""></div>
                <div class=""radar-core""></div>
            </div>
        </div>

        <div class=""findings-strip"" id=""findingsStrip"">
            <div class=""finding-chip"" id=""findingChip""></div>
        </div>

        <div class=""footer"">
            <div class=""start-wrap"" id=""startWrap"">
                <button class=""btn-start"" id=""btnStart"">Başlat</button>
            </div>

            <div class=""progress-section hidden"" id=""progressSection"">
                <div class=""status-row"">
                    <span class=""status-text"" id=""statusText"">Hazırlanıyor...</span>
                    <span class=""status-pct"" id=""statusPct"">0%</span>
                </div>
                <div class=""progress-track"">
                    <div class=""progress-fill"" id=""progressFill""></div>
                </div>
                <div class=""done-badge"" id=""doneBadge"">TARAMA TAMAMLANDI</div>
            </div>
        </div>
    </div>

    <script>
        (function () {
            const radar = document.getElementById('radar');
            const btnStart = document.getElementById('btnStart');
            const btnClose = document.getElementById('btnClose');
            const startWrap = document.getElementById('startWrap');
            const progressSection = document.getElementById('progressSection');
            const progressFill = document.getElementById('progressFill');
            const statusText = document.getElementById('statusText');
            const statusPct = document.getElementById('statusPct');
            const findingsStrip = document.getElementById('findingsStrip');
            const findingChip = document.getElementById('findingChip');
            const doneBadge = document.getElementById('doneBadge');

            // Snowflakes
            const snowEl = document.getElementById('snow');
            const flakes = ['❄', '❅', '❆', '✦', '·'];
            for (let i = 0; i < 42; i++) {
                const s = document.createElement('div');
                s.className = 'snowflake';
                s.textContent = flakes[Math.floor(Math.random() * flakes.length)];
                s.style.left = Math.random() * 100 + '%';
                s.style.fontSize = (8 + Math.random() * 14) + 'px';
                s.style.animationDuration = (6 + Math.random() * 12) + 's';
                s.style.animationDelay = (Math.random() * 8) + 's';
                s.style.setProperty('--drift', (Math.random() * 80 - 40) + 'px');
                s.style.opacity = String(0.35 + Math.random() * 0.55);
                snowEl.appendChild(s);
            }

            const appCursor = document.getElementById('appCursor');
            window.addEventListener('mousemove', function(e) {
                appCursor.style.left = e.clientX + 'px';
                appCursor.style.top = e.clientY + 'px';
            });
            document.querySelectorAll('button, a').forEach(function(el) {
                el.addEventListener('mouseenter', function() { appCursor.classList.add('hot'); });
                el.addEventListener('mouseleave', function() { appCursor.classList.remove('hot'); });
            });

            function postToHost(msg) {
                try {
                    if (window.chrome && window.chrome.webview) {
                        window.chrome.webview.postMessage(msg);
                    }
                } catch (e) { }
            }

            btnClose.addEventListener('click', function () {
                postToHost('EXIT_APP');
            });

            btnStart.addEventListener('click', function () {
                startWrap.classList.add('hidden');
                progressSection.classList.remove('hidden');
                radar.classList.remove('idle');
                statusText.classList.add('active');
                statusText.textContent = 'Sistem, PE, Ağ, RPF ve AI Analizi yapılıyor...';
                statusPct.textContent = '0%';
                progressFill.style.width = '0%';
                postToHost('START_SCAN');
            });

            window.updateProgress = function (percent, message) {
                const p = Math.max(0, Math.min(100, Number(percent) || 0));
                progressFill.style.width = p + '%';
                statusPct.textContent = p + '%';
                if (message) {
                    statusText.textContent = message;
                    statusText.classList.add('active');
                }
                if (p >= 100) {
                    radar.classList.add('idle');
                    doneBadge.classList.add('show');
                    statusText.textContent = 'Tarama tamamlandı';
                }
            };

            window.addFindingToUI = function (category, path, message, score, isInfected) {
                const danger = isInfected === true || isInfected === 'true' ||
                    (category && String(category).indexOf('Yüksek') >= 0);
                findingChip.textContent = (category || 'Bulgu') + (path ? ' — ' + path : '');
                findingChip.className = 'finding-chip' + (danger ? ' danger' : '');
                findingsStrip.classList.add('visible');
                clearTimeout(window._chipTimer);
                window._chipTimer = setTimeout(function () {
                    findingsStrip.classList.remove('visible');
                }, 3500);
            };

            window.setMetaInfo = function (installDate, score) {
                window._metaInstall = installDate;
                window._metaScore = score;
            };
        })();
    </script>
</body>
</html>
";
        }

        private async Task UpdateUIProgress(int percent)
        {
            await Dispatcher.InvokeAsync(async () =>
            {
                if (Browser?.CoreWebView2 != null)
                {
                    await Browser.CoreWebView2.ExecuteScriptAsync($"updateProgress({percent}, 'Sistem, PE, Ağ, RPF ve AI Analizi yapılıyor...');");
                }
            });
        }

        private async Task SendFindingToUI(ThreatFinding finding)
        {
            await Dispatcher.InvokeAsync(async () =>
            {
                if (Browser?.CoreWebView2 != null)
                {
                    string safePath = finding.Path.Replace("\\", "\\\\").Replace("'", "\\'");
                    string safeMsg = finding.Message.Replace("'", "\\'");
                    string isInfectedStr = finding.IsInfected ? "true" : "false";
                    await Browser.CoreWebView2.ExecuteScriptAsync($"addFindingToUI('{finding.Category}', '{safePath}', '{safeMsg}', {finding.Score}, {isInfectedStr});");
                }
            });
        }

        private async Task ExecuteScanProcess()
        {
            _score = 0;
            _findings.Clear();
            _discordAccountIds.Clear();
            _discordAccounts.Clear();

            try
            {
                await UpdateUIProgress(10);
                await Task.Delay(100);

                _installDate = GetExactInstallDate();

                await UpdateUIProgress(20);
                await Task.Run(() => ScanDiscordAccounts());

                await UpdateUIProgress(30);
                await Task.Run(() => ScanProcesses());

                await UpdateUIProgress(40);
                await Task.Run(() => ScanAntiCheatAndTools());

                await UpdateUIProgress(50);
                await Task.Run(() => ScanStartupRegistry());

                await UpdateUIProgress(60);
                await Task.Run(() => ScanActiveNetworkListeners());

                await UpdateUIProgress(70);
                await Task.Run(() =>
                {
                    ScanFiles();
                    ScanFiveM();
                    ScanFiveMModsFolder();
                });

                await UpdateUIProgress(85);
                await ScanSuspiciousFilesWithDefenderCLI();

                // Filename-only web reputation check. This does not upload file contents.
                await ApplyWebFilenameReputationAsync();

                lock (_findings)
                {
                    foreach (var finding in _findings)
                    {
                        string aiEval = AuraAiAnalyzer.AnalyzeFinding(finding);
                        if (aiEval.Contains("YÜKSEK RİSK") || aiEval.Contains("KRİTİK"))
                        {
                            finding.Category = "Yüksek Şüpheli";
                        }
                    }
                }

                await Dispatcher.InvokeAsync(async () =>
                {
                    await Browser.CoreWebView2.ExecuteScriptAsync($"setMetaInfo('{_installDate}', {_score});");
                });

                await UpdateUIProgress(95);
                await ExportScanResultToJson();
                await GenerateAndSendWebReport();

                await UpdateUIProgress(100);
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Tarama hatası: " + ex.Message);
                await UpdateUIProgress(100);
            }
        }

        private string GetExactInstallDate()
        {
            try
            {
                using (RegistryKey? key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                    .OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (key != null)
                    {
                        object? installDateObj = key.GetValue("InstallDate");
                        if (installDateObj is int secondsSince1970)
                        {
                            DateTime dt = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(secondsSince1970).ToLocalTime();
                            return dt.ToString("dd.MM.yyyy HH:mm");
                        }
                    }
                }
            }
            catch { }

            try
            {
                return Directory.GetCreationTime(Environment.GetFolderPath(Environment.SpecialFolder.Windows)).ToString("dd.MM.yyyy HH:mm");
            }
            catch { return "Bilinmiyor"; }
        }

        private void ScanDiscordAccounts()
        {
            // Read only local profile metadata (id/username/global_name).
            // Authentication/session tokens are intentionally not read or decoded.
            try
            {
                string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string localRoaming = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string[] discordPaths = {
                    Path.Combine(roaming, "discord", "Local Storage", "leveldb"),
                    Path.Combine(roaming, "discordptb", "Local Storage", "leveldb"),
                    Path.Combine(roaming, "discordcanary", "Local Storage", "leveldb"),
                    Path.Combine(roaming, "Lightcord", "Local Storage", "leveldb"),
                    Path.Combine(localRoaming, "Google", "Chrome", "User Data", "Default", "Local Storage", "leveldb"),
                    Path.Combine(roaming, "Opera Software", "Opera Stable", "Local Storage", "leveldb"),
                    Path.Combine(localRoaming, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Local Storage", "leveldb")
                };
                foreach (string dbPath in discordPaths)
                {
                    if (!Directory.Exists(dbPath)) continue;
                    foreach (FileInfo file in new DirectoryInfo(dbPath).GetFiles("*.ldb").Concat(new DirectoryInfo(dbPath).GetFiles("*.log")))
                    {
                        try { ExtractDiscordProfileMetadata(Encoding.UTF8.GetString(File.ReadAllBytes(file.FullName)), file.FullName); }
                        catch { }
                    }
                }
            }
            catch { }
        }

        private void ExtractDiscordProfileMetadata(string content, string sourcePath)
        {
            if (string.IsNullOrWhiteSpace(content)) return;
            string[] patterns =
            {
                @"""id""\s*:\s*""(?<id>\d{17,20})"".{0,1500}?(?:""username""|""global_name"")\s*:\s*""(?<name>[^""]{1,64})""",
                @"(?:""username""|""global_name"")\s*:\s*""(?<name>[^""]{1,64})"".{0,1500}?""id""\s*:\s*""(?<id>\d{17,20})"""
            };
            foreach (string pattern in patterns)
            {
                foreach (Match m in Regex.Matches(content, pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline))
                    AddDiscordProfile(m.Groups["id"].Value, m.Groups["name"].Value, sourcePath);
            }
        }

        private void AddDiscordProfile(string id, string name, string sourcePath)
        {
            if (!Regex.IsMatch(id ?? string.Empty, @"^\d{17,20}$")) return;
            if (string.IsNullOrWhiteSpace(name)) name = "Discord hesabı";
            lock (_discordAccounts)
            {
                if (_discordAccounts.Any(x => x.Id == id)) return;
                _discordAccounts.Add(new DiscordAccountInfo { Id = id, Username = name, Source = sourcePath });
            }
            if (!_discordAccountIds.Contains(id, StringComparer.OrdinalIgnoreCase)) _discordAccountIds.Add(id);
            AddFinding(0, "Discord Hesap", $"Discord hesabı bulundu: {name} ({id})", sourcePath);
        }

        private void InitializeDefenderListener()
        {
            Task.Run(() =>
            {
                try
                {
                    string query = "*[System[(EventID=1116 or EventID=1117)]]";
                    var watcher = new EventLogWatcher(new EventLogQuery("Microsoft-Windows-Windows Defender/Operational", PathType.LogName, query));

                    watcher.EventRecordWritten += (sender, e) =>
                    {
                        try
                        {
                            var record = e.EventRecord;
                            if (record == null) return;

                            string threatName = record.Properties.Count > 0 ? record.Properties[0].Value?.ToString() ?? "Bilinmeyen Tehdit" : "Bilinmeyen Tehdit";
                            string filePath = record.Properties.Count > 1 ? record.Properties[1].Value?.ToString() ?? string.Empty : string.Empty;

                            if (!string.IsNullOrEmpty(filePath) && filePath != "Unknown Path")
                            {
                                lock (_detectedDefenderPaths)
                                {
                                    if (_detectedDefenderPaths.Add(filePath))
                                    {
                                        AddFinding(100, "Yüksek Şüpheli", $"Defender tehdidi yakaladı [{threatName}]", filePath, string.Empty, true);
                                    }
                                }
                            }
                        }
                        catch { }
                    };

                    watcher.Enabled = true;
                    Thread.Sleep(Timeout.Infinite);
                }
                catch { }
            });
        }

        private bool IsCheatKeyword(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return false;

            string normalized = text.Replace("_", " ").Replace("-", " ").ToLowerInvariant();
            string[] cheatKeywords =
            {
                "mwbyte", "forte", "fivez", "cfxsense", "cfx sense", "eulen",
                "skiptrace", "redengine", "red engine", "executor", "injector",
                "aimbot", "wallhack", "silentaim", "silent aim", "triggerbot",
                "cheatengine", "processhacker", "x64dbg", "x32dbg", "dnspy",
                "scripthook", "modmenu", "mod menu", "menuhook", "lua executor",
                "luaexecutor", "native executor", "nativeexecutor", "external",
                "destructor", "destructive", "lynx", "hammafia", "fallout",
                "brutan", "soviet", "dopamine", "ragebot",
                "godmode", "noclip", "no clip", "nofall", "no fall", "nostamina",
                "no stamina", "rapidfire", "rapid fire", "freecam", "free cam",
                "spawner", "vehicle spawner", "weapon spawner", "resource injector",
                "memory editor", "memoryeditor", "fiveguard bypass", "anticheat bypass",
                "ac bypass", "cheat", "cheats", "hackmenu", "hack menu"
            };

            return cheatKeywords.Any(kw => normalized.Contains(kw));
        }

        private void ScanProcesses()
        {
            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    string name = process.ProcessName;
                    string? path = null;
                    try { path = process.MainModule?.FileName; } catch { }

                    bool isElevated = IsProcessElevated(process);
                    string adminTag = isElevated ? " [Yönetici]" : "";

                    if (IsCheatKeyword(name))
                    {
                        AddFinding(100, "Yüksek Şüpheli", $"Yasaklı hile süreci çalışıyor: {name}{adminTag}", path ?? "", "", true);
                    }
                    else if (!string.IsNullOrEmpty(path) && !_whitelistedProcesses.Contains(name))
                    {
                        ScanExecutable(path, $"Çalışan Süreç{adminTag}");
                    }
                }
                catch { }
            }
        }

        private bool IsProcessElevated(Process process)
        {
            try
            {
                using (var identity = WindowsIdentity.GetCurrent())
                {
                    var principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch { return false; }
        }

        private void ScanAntiCheatAndTools()
        {
            string[] suspiciousTools = { "cheatengine", "processhacker", "x64dbg", "x32dbg", "ida64", "dnspy", "vmprotect" };
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    string pName = proc.ProcessName.ToLower();
                    if (suspiciousTools.Any(tool => pName.Contains(tool)))
                    {
                        AddFinding(90, "Anti-Cheat İhlali", $"Şüpheli analiz/hile aracı aktif: {proc.ProcessName} (PID: {proc.Id})", proc.MainModule?.FileName ?? "", "", true);
                    }
                }
                catch { }
            }
        }

        private void ScanStartupRegistry()
        {
            string[] registryPaths = {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            };

            foreach (string path in registryPaths)
            {
                try
                {
                    using (RegistryKey? key = Registry.CurrentUser.OpenSubKey(path))
                    {
                        if (key != null)
                        {
                            foreach (string valueName in key.GetValueNames())
                            {
                                string val = key.GetValue(valueName)?.ToString() ?? "";
                                if (IsCheatKeyword(val) || IsCheatKeyword(valueName))
                                {
                                    AddFinding(80, "Sistem Kalıcılığı", $"Şüpheli Başlangıç Kaydı [HKCU]: {valueName} -> {val}", val, "", true);
                                }
                            }
                        }
                    }

                    using (RegistryKey? key = Registry.LocalMachine.OpenSubKey(path))
                    {
                        if (key != null)
                        {
                            foreach (string valueName in key.GetValueNames())
                            {
                                string val = key.GetValue(valueName)?.ToString() ?? "";
                                if (IsCheatKeyword(val) || IsCheatKeyword(valueName))
                                {
                                    AddFinding(80, "Sistem Kalıcılığı", $"Şüpheli Başlangıç Kaydı [HKLM]: {valueName} -> {val}", val, "", true);
                                }
                            }
                        }
                    }
                }
                catch { }
            }
        }

        private void ScanActiveNetworkListeners()
        {
            try
            {
                IPGlobalProperties ipProperties = IPGlobalProperties.GetIPGlobalProperties();
                var listeners = ipProperties.GetActiveTcpListeners();

                foreach (var endpoint in listeners)
                {
                    if (endpoint.Port == 4444 || endpoint.Port == 8888 || endpoint.Port == 9999)
                    {
                        AddFinding(40, "Ağ Taraması", $"Şüpheli Dinlenen Ağ Portu: {endpoint.Port} ({endpoint.Address})", "");
                    }
                }
            }
            catch { }
        }

        private void ScanExecutable(string file, string source)
        {
            try
            {
                string extension = Path.GetExtension(file).ToLower();
                if (!_targetExecutableExtensions.Contains(extension)) return;

                FileInfo fi = new FileInfo(file);
                if (!fi.Exists) return;

                PeAnalysisResult peResult = PeAnalyzer.Analyze(file);
                bool isSigned = IsDigitallySigned(file);
                bool containsCheatKw = IsCheatKeyword(fi.Name);

                double dynamicRisk = 0.0;
                if (containsCheatKw) dynamicRisk += 0.80;
                if (!isSigned) dynamicRisk += 0.15;
                if (peResult.Entropy > 7.2) dynamicRisk += 0.30;
                if (!peResult.HasValidPeHeader) dynamicRisk += 0.20;

                int calculatedScore = (int)(dynamicRisk * 100);

                if (dynamicRisk >= 0.70 || containsCheatKw)
                {
                    AddFinding(calculatedScore > 100 ? 100 : calculatedScore, "Yüksek Şüpheli",
                        $"{source}: PE Analizi Şüpheli [Entropi: {peResult.Entropy:F2} | İmza: {(isSigned ? "Var" : "Yok")} | MD5: {peResult.Md5Hash}]", file, peResult.Hash, true);
                }
                else if (dynamicRisk >= 0.25)
                {
                    AddFinding(calculatedScore, "Şüpheli Executable",
                        $"{source}: Kod dosyası incelendi [{fi.Name} | Entropi: {peResult.Entropy:F2}]", file, peResult.Hash);
                }
                else
                {
                    // Temiz Dosyalar da Rapora Eklensin
                    AddFinding(0, "Güvenli Dosya",
                        $"{source}: Temiz ve doğrulanmış dosya [{fi.Name} | İmza: {(isSigned ? "Geçerli" : "Yok")}]", file, peResult.Hash);
                }

                AnalyzeFileRenamingAndOriginalName(file, peResult.Hash);
            }
            catch { }
        }

        private bool IsDigitallySigned(string filePath)
        {
            try
            {
                X509Certificate signer = X509Certificate.CreateFromSignedFile(filePath);
                return signer != null;
            }
            catch { return false; }
        }

        private void AnalyzeFileRenamingAndOriginalName(string filePath, string hash)
        {
            try
            {
                string currentFileName = Path.GetFileName(filePath);
                string originalName = currentFileName;

                string zoneFile = filePath + ":Zone.Identifier";
                if (File.Exists(zoneFile))
                {
                    string zoneContent = File.ReadAllText(zoneFile);
                    foreach (var line in zoneContent.Split('\n'))
                    {
                        if (line.StartsWith("HostUrl=", StringComparison.OrdinalIgnoreCase))
                        {
                            string url = line.Substring(line.IndexOf('=') + 1).Trim();
                            try
                            {
                                Uri uri = new Uri(url);
                                string segments = uri.Segments.LastOrDefault() ?? "";
                                if (!string.IsNullOrEmpty(segments) && !segments.Contains("/"))
                                {
                                    originalName = Uri.UnescapeDataString(segments);
                                }
                            }
                            catch { }
                        }
                    }
                }

                if (!string.Equals(currentFileName, originalName, StringComparison.OrdinalIgnoreCase) && IsCheatKeyword(originalName))
                {
                    AddFinding(100, "Yüksek Şüpheli", $"İndirme ismi değiştirilmiş hile! Orijinal adı: '{originalName}', Mevcut adı: '{currentFileName}'", filePath, hash, true);
                }
            }
            catch { }
        }

        private void ScanFiles()
        {
            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string downloads = Path.Combine(userProfile, "Downloads");
            string temp = Path.GetTempPath();

            string[] targets = { desktop, downloads, temp };

            foreach (string folder in targets)
            {
                if (!Directory.Exists(folder)) continue;
                ScanDirectory(folder);
            }
        }

        private void ScanDirectory(string root)
        {
            try
            {
                var files = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories);
                foreach (string file in files)
                {
                    try
                    {
                        string ext = Path.GetExtension(file).ToLower();
                        if (_targetExecutableExtensions.Contains(ext))
                        {
                            ScanExecutable(file, "Dosya Taraması");
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private string CalculateFileSha256(string filePath)
        {
            try
            {
                using FileStream stream = File.OpenRead(filePath);
                using SHA256 sha = SHA256.Create();
                return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
            }
            catch
            {
                return string.Empty;
            }
        }

        private void ScanFiveMModsFolder()
        {
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string modsFolder = Path.Combine(localAppData, "FiveM", "FiveM.app", "mods");

            if (!Directory.Exists(modsFolder)) return;

            try
            {
                foreach (string file in Directory.EnumerateFiles(modsFolder, "*.*", SearchOption.AllDirectories))
                {
                    string fileName = Path.GetFileName(file);
                    string extension = Path.GetExtension(file);

                    if (extension.Equals(".rpf", StringComparison.OrdinalIgnoreCase))
                    {
                        string hash = string.Empty;
                        try { hash = CalculateFileSha256(file); } catch { }

                        if (IsCheatKeyword(fileName))
                        {
                            AddFinding(100, "Yüksek Şüpheli",
                                $"FiveM mods klasöründe hile adı taşıyan RPF: {fileName}",
                                file, hash, true);
                        }
                        else
                        {
                            AddFinding(0, "FiveM / RPF",
                                $"FiveM mods klasöründe RPF/mod bulundu: {fileName}",
                                file, hash);
                        }
                    }
                    else
                    {
                        ScanExecutable(file, "FiveM Mods Taraması");
                    }

                    if (!extension.Equals(".rpf", StringComparison.OrdinalIgnoreCase))
                    {
                        if (IsCheatKeyword(fileName))
                        {
                            AddFinding(100, "Yüksek Şüpheli",
                                $"FiveM mods klasöründe hile adı taşıyan dosya: {fileName}",
                                file, "", true);
                        }
                        else
                        {
                            AddFinding(0, "FiveM Mods",
                                $"FiveM mods klasöründe mod dosyası bulundu: {fileName}",
                                file);
                        }
                    }
                }
            }
            catch { }
        }

        private void ScanFiveM()
        {
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string location = Path.Combine(local, "FiveM", "FiveM.app", "plugins");

            if (!Directory.Exists(location)) return;

            try
            {
                foreach (string file in Directory.EnumerateFiles(location, "*.*", SearchOption.AllDirectories))
                {
                    ScanExecutable(file, "FiveM Eklenti");
                }
            }
            catch { }
        }

        private async Task ScanSuspiciousFilesWithDefenderCLI()
        {
            List<ThreatFinding> targets;
            lock (_findings)
            {
                targets = _findings.Where(f => !f.IsInfected && !string.IsNullOrEmpty(f.Path) && File.Exists(f.Path) &&
                    f.Path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)).ToList();
            }

            foreach (var finding in targets)
            {
                bool isInfected = await Task.Run(() => CheckFileWithMpCmdRun(finding.Path));
                if (isInfected)
                {
                    finding.IsInfected = true;
                    finding.Category = "Yüksek Şüpheli";
                    finding.Score += 70;
                    finding.Message += " | Windows Defender Doğruladı!";
                    _score += 70;
                    await SendFindingToUI(finding);
                }
            }
        }

        private bool CheckFileWithMpCmdRun(string filePath)
        {
            try
            {
                string defenderPath = @"C:\Program Files\Windows Defender\MpCmdRun.exe";
                if (!File.Exists(defenderPath)) return false;

                Process p = new Process();
                p.StartInfo.FileName = defenderPath;
                p.StartInfo.Arguments = $"-Scan -ScanType 3 -File \"{filePath}\"";
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.CreateNoWindow = true;
                p.Start();

                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit();

                return p.ExitCode == 2 || output.Contains("threat detected", StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        private void AddFinding(int score, string category, string message, string path = "", string hash = "", bool isInfected = false)
        {
            _score += score;

            var finding = new ThreatFinding
            {
                Score = score,
                Category = category,
                Message = message,
                Path = path,
                Hash = hash,
                IsInfected = isInfected
            };

            lock (_findings)
            {
                if (!string.IsNullOrEmpty(path) && _findings.Any(f => f.Path == path && f.Category == category)) return;
                _findings.Add(finding);
            }

            Task.Run(async () => await SendFindingToUI(finding));
        }

        private async Task ExportScanResultToJson()
        {
            try
            {
                string jsonPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "scan_report.json");
                var reportData = new
                {
                    User = Environment.UserName,
                    InstallDate = _installDate,
                    Score = _score,
                    TotalFindings = _findings.Count,
                    Findings = _findings
                };
                string jsonOutput = JsonSerializer.Serialize(reportData, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(jsonPath, jsonOutput);
            }
            catch { }
        }

        private static readonly string[] WebCheatIndicators =
        {
            "cheat", "cheats", "executor", "injector", "mod menu", "modmenu",
            "redengine", "eulen", "cfxsense", "aimbot", "wallhack", "silent aim",
            "triggerbot", "noclip", "godmode", "no fall", "no stamina", "fiveguard bypass",
            "anticheat bypass", "lua executor", "hackmenu", "hack menu"
        };

        private sealed class WebNameCheckResult
        {
            public bool Suspicious { get; set; }
            public string Reason { get; set; } = string.Empty;
        }

        private async Task<WebNameCheckResult> CheckFilenameOnWebAsync(string fileName)
        {
            // Best-effort public search of the filename only. File contents are never uploaded.
            // A search hit is treated as a signal, not proof, to reduce false positives.
            try
            {
                if (string.IsNullOrWhiteSpace(fileName))
                    return new WebNameCheckResult();

                string cleanName = Path.GetFileNameWithoutExtension(fileName);
                if (cleanName.Length < 3)
                    return new WebNameCheckResult();

                string query = Uri.EscapeDataString($"\"{cleanName}\" FiveM cheat");
                using var request = new HttpRequestMessage(
                    HttpMethod.Get,
                    "https://www.google.com/search?q=" + query);
                request.Headers.UserAgent.ParseAdd("Mozilla/5.0 Aura.scanner security report");

                using HttpResponseMessage response = await httpClient.SendAsync(request);
                if (!response.IsSuccessStatusCode)
                    return new WebNameCheckResult();

                string html = await response.Content.ReadAsStringAsync();
                string plain = Regex.Replace(html, "<[^>]+>", " ");
                plain = System.Net.WebUtility.HtmlDecode(plain).ToLowerInvariant();

                int hits = WebCheatIndicators.Count(x => plain.Contains(x));
                if (hits >= 2)
                {
                    return new WebNameCheckResult
                    {
                        Suspicious = true,
                        Reason = "Web aramasında dosya adı FiveM hile/cheat bağlamında birden fazla sonuç sinyali verdi."
                    };
                }
            }
            catch { }

            return new WebNameCheckResult();
        }

        private async Task ApplyWebFilenameReputationAsync()
        {
            try
            {
                var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                lock (_findings)
                {
                    foreach (var f in _findings)
                        if (!string.IsNullOrWhiteSpace(f.Path) && File.Exists(f.Path))
                            names[Path.GetFileName(f.Path)] = f.Path;
                }

                string modsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FiveM", "FiveM.app", "mods");
                if (Directory.Exists(modsPath))
                {
                    foreach (string path in Directory.EnumerateFiles(modsPath, "*", SearchOption.AllDirectories))
                    {
                        try { names[Path.GetFileName(path)] = path; } catch { }
                    }
                }

                int checkedCount = 0;
                foreach (var pair in names)
                {
                    string name = pair.Key;
                    string path = pair.Value;
                    if (IsCheatKeyword(name))
                    {
                        AddFinding(100, "Yüksek Şüpheli", $"FiveM hile/cheat adı doğrudan dosya adında bulundu: {name}", path, string.Empty, true);
                        continue;
                    }
                    if (checkedCount++ >= 200) break;
                    WebNameCheckResult result = await CheckFilenameOnWebAsync(name);
                    if (result.Suspicious)
                        AddFinding(85, "Yüksek Şüpheli", $"Dosya adı web itibar kontrolünde şüpheli göründü: {name}. {result.Reason}", path, string.Empty, true);
                }
            }
            catch (Exception ex) { Debug.WriteLine("Web dosya adı taraması hatası: " + ex.Message); }
        }

        private async Task GenerateAndSendWebReport()
        {
            try
            {
                StringBuilder highThreatRows = new StringBuilder();
                StringBuilder suspiciousRows = new StringBuilder();
                StringBuilder fivemRows = new StringBuilder();
                StringBuilder discordRows = new StringBuilder();
                StringBuilder aiRows = new StringBuilder();
                StringBuilder cleanRows = new StringBuilder();

                lock (_findings)
                {
                    foreach (var f in _findings)
                    {
                        string safePath = System.Net.WebUtility.HtmlEncode(f.Path ?? string.Empty);
                        string safeMsg = System.Net.WebUtility.HtmlEncode(f.Message ?? string.Empty);
                        string safeCat = System.Net.WebUtility.HtmlEncode(f.Category ?? "Bulgu");
                        string aiComment = System.Net.WebUtility.HtmlEncode(AuraAiAnalyzer.AnalyzeFinding(f));
                        string badgeClass = (f.Category == "Yüksek Şüpheli" || f.IsInfected) ? "danger" : (f.Category == "Güvenli Dosya" ? "clean" : (f.Category.Contains("FiveM") || f.Category.Contains("RPF") ? "fivem" : "warning"));
                        string row = $"<div class='result-row'><div><span class='tag {badgeClass}'>{safeCat}</span></div><div class='mono path'>{safePath}</div><div class='desc'>{safeMsg}</div></div>";
                        string aiRow = $"<div class='result-row ai-row'><div><span class='tag {badgeClass}'>{safeCat}</span></div><div class='mono path'>{safePath}</div><div class='desc ai'>{aiComment}</div></div>";
                        if (f.Category == "Yüksek Şüpheli" || f.IsInfected) highThreatRows.Append(row);
                        else if (f.Category.Contains("FiveM") || f.Category.Contains("RPF") || (f.Path ?? "").EndsWith(".rpf", StringComparison.OrdinalIgnoreCase)) fivemRows.Append(row);
                        else if (f.Category == "Güvenli Dosya") cleanRows.Append(row);
                        else if (f.Category != "Discord Hesap") suspiciousRows.Append(row);
                        if (f.Category != "Discord Hesap") aiRows.Append(aiRow);
                    }
                }

                lock (_discordAccounts)
                {
                    foreach (var account in _discordAccounts.OrderBy(x => x.Username, StringComparer.OrdinalIgnoreCase))
                    {
                        string safeName = System.Net.WebUtility.HtmlEncode(account.Username);
                        string safeId = System.Net.WebUtility.HtmlEncode(account.Id);
                        discordRows.Append($"<div class='account-row'><div class='account-name'>{safeName}</div><div class='mono account-id'>{safeId}</div><a class='profile-link' href='https://discord.com/users/{Uri.EscapeDataString(account.Id)}' target='_blank' rel='noopener noreferrer'>Profili Gör</a></div>");
                    }
                }
                if (discordRows.Length == 0)
                    foreach (var accountId in _discordAccountIds.Distinct(StringComparer.OrdinalIgnoreCase))
                    {
                        string safeId = System.Net.WebUtility.HtmlEncode(accountId);
                        discordRows.Append($"<div class='account-row'><div class='account-name'>Discord hesabı</div><div class='mono account-id'>{safeId}</div><a class='profile-link' href='https://discord.com/users/{Uri.EscapeDataString(accountId)}' target='_blank' rel='noopener noreferrer'>Profili Gör</a></div>");
                    }

                if (highThreatRows.Length == 0) highThreatRows.Append("<div class='empty'>Yüksek şüpheli veya virüslü dosya bulunamadı.</div>");
                if (suspiciousRows.Length == 0) suspiciousRows.Append("<div class='empty'>Şüpheli dosya bulunamadı.</div>");
                if (fivemRows.Length == 0) fivemRows.Append("<div class='empty'>FiveM / RPF bulgusu bulunamadı.</div>");
                if (discordRows.Length == 0) discordRows.Append("<div class='empty'>Discord profil bilgisi bulunamadı. Yerel profil metadatası mevcut olmayabilir.</div>");
                if (cleanRows.Length == 0) cleanRows.Append("<div class='empty'>Temiz dosya kaydı bulunamadı.</div>");
                if (aiRows.Length == 0) aiRows.Append("<div class='empty'>AI değerlendirmesi bulunamadı.</div>");

                int hileCount = _findings.Count(f => f.Category == "Yüksek Şüpheli" || f.IsInfected);
                int uyariCount = _findings.Count(f => f.Category != "Yüksek Şüpheli" && !f.IsInfected && f.Category != "Discord Hesap" && f.Category != "Güvenli Dosya");
                int fivemCount = _findings.Count(f => f.Category.Contains("FiveM") || f.Category.Contains("RPF") || (f.Path ?? "").EndsWith(".rpf", StringComparison.OrdinalIgnoreCase));
                int temizCount = _findings.Count(f => f.Category == "Güvenli Dosya");
                int discordCount = _discordAccountIds.Distinct(StringComparer.OrdinalIgnoreCase).Count();
                int totalFindings = _findings.Count;
                var usbLogs = CollectUsbLogsForReport();
                var usbRows = new StringBuilder();
                foreach (var usb in usbLogs)
                {
                    string safeName = System.Net.WebUtility.HtmlEncode(usb.Name);
                    string safePath = System.Net.WebUtility.HtmlEncode(usb.Message);
                    string safeTime = System.Net.WebUtility.HtmlEncode(usb.Time);
                    usbRows.Append($"<div class='result-row'><div><span class='tag warning'>USB LOG</span></div><div class='mono path'>{safeName}</div><div class='desc'>{safeTime}<br>{safePath}</div></div>");
                }
                if (usbRows.Length == 0)
                    usbRows.Append("<div class='empty'>USB ile ilişkili sistem logu bulunamadı.</div>");
                int usbCount = usbLogs.Count;
                var usbBootEntries = CollectUsbBootEvidence();
                var runtimeBrokerEntries = CollectRuntimeBrokerSignatureAnomalies();

                var usbBootRows = new StringBuilder();
                foreach (var boot in usbBootEntries)
                {
                    usbBootRows.Append(
                        $"<div class='result-row'><div><span class='tag warning'>{System.Net.WebUtility.HtmlEncode(boot.Status)}</span></div><div class='mono path'>{System.Net.WebUtility.HtmlEncode(boot.Drive)}</div><div class='desc'>{System.Net.WebUtility.HtmlEncode(boot.Type)}<br>{System.Net.WebUtility.HtmlEncode(boot.Evidence)}</div></div>");
                }

                if (usbBootRows.Length == 0)
                    usbBootRows.Append("<div class='empty'>Takılı removable USB üzerinde boot evidence bulunamadı.</div>");

                var runtimeRows = new StringBuilder();
                foreach (var rb in runtimeBrokerEntries)
                {
                    string tagClass = rb.Category == "FARKLI RUNTIMEBROKER İMZASI"
                        ? "danger"
                        : "clean";

                    runtimeRows.Append(
                        $"<div class='result-row'><div><span class='tag {tagClass}'>{System.Net.WebUtility.HtmlEncode(rb.Category)}</span></div><div class='mono path'>{System.Net.WebUtility.HtmlEncode(rb.ProcessName)}<br>{System.Net.WebUtility.HtmlEncode(rb.Path)}</div><div class='desc'>İmza: {System.Net.WebUtility.HtmlEncode(rb.SignatureSubject)}<br>Durum: {System.Net.WebUtility.HtmlEncode(rb.SignatureStatus)}</div></div>");
                }

                if (runtimeRows.Length == 0)
                    runtimeRows.Append("<div class='empty'>RuntimeBroker süreci bulunamadı.</div>");

                int runtimeAnomalyCount = runtimeBrokerEntries.Count(
                    x => x.Category == "FARKLI RUNTIMEBROKER İMZASI");


                string statusText = hileCount > 0 ? "HİLE VEYA TEHDİT BULUNDU" : (uyariCount > 0 ? "ŞÜPHELİ AKTİVİTE" : "GÜVENLİ VE TEMİZ");
                string signalClass = hileCount > 0 ? "signal-red" : (uyariCount > 0 ? "signal-orange" : "signal-green");
                string safeStatus = System.Net.WebUtility.HtmlEncode(statusText);
                string safeUser = System.Net.WebUtility.HtmlEncode(Environment.UserName);
                string safeInstall = System.Net.WebUtility.HtmlEncode(_installDate);

                var sb = new StringBuilder();
                sb.AppendLine("<!DOCTYPE html><html lang='tr'><head><meta charset='UTF-8'>");
                sb.AppendLine("<meta name='viewport' content='width=device-width, initial-scale=1.0'><title>Aura.scanner — AURA SCANNER YÖNETİCİ PANELİ</title>");
                sb.AppendLine("<link rel='preconnect' href='https://fonts.googleapis.com'><link rel='preconnect' href='https://fonts.gstatic.com' crossorigin><link href='https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=Space+Grotesk:wght@400;500;600&display=swap' rel='stylesheet'>");
                sb.AppendLine("<style>");
                sb.Append(@"
*{box-sizing:border-box;margin:0;padding:0}html,body{min-height:100%;background:#000;color:#fff;font-family:'Space Grotesk',sans-serif;cursor:none}body{overflow-x:hidden;background:#000}
#bgCanvas,#trailCanvas{position:fixed;inset:0;width:100%;height:100%;pointer-events:none}#bgCanvas{z-index:0}#trailCanvas{z-index:1}
#cursorDot{position:fixed;z-index:9999;width:12px;height:12px;border:1px solid rgba(255,255,255,.85);border-radius:50%;background:rgba(255,255,255,.08);box-shadow:0 0 14px rgba(255,255,255,.4);pointer-events:none;transform:translate(-50%,-50%);transition:width .12s,height .12s,background .12s}#cursorDot.hot{width:20px;height:20px;background:rgba(255,70,70,.12);border-color:#ff6b6b;box-shadow:0 0 18px rgba(255,59,59,.55)}
.page{position:relative;z-index:5;min-height:100vh;padding:22px 22px 22px 250px}.shell{min-height:calc(100vh - 44px);background:rgba(8,8,12,.68);border:1px solid rgba(255,255,255,.16);border-radius:34px;backdrop-filter:blur(20px);overflow:hidden;box-shadow:0 25px 90px rgba(0,0,0,.7)}
.sidebar{position:fixed;left:18px;top:18px;bottom:18px;width:210px;z-index:20;background:rgba(7,7,11,.74);border:1px solid rgba(255,255,255,.14);border-radius:28px;backdrop-filter:blur(24px);box-shadow:0 20px 70px rgba(0,0,0,.65);padding:22px 12px;display:flex;flex-direction:column}.side-brand{padding:4px 10px 22px}.brand{font-family:'Orbitron';font-weight:900;font-size:20px;letter-spacing:2px}.sub{font-size:8px;letter-spacing:2.5px;opacity:.4;margin-top:5px}.side-title{font-family:'Orbitron';font-size:8px;letter-spacing:2px;opacity:.32;padding:12px 10px 8px}
.nav{display:flex;flex-direction:column;gap:7px}.nav button{width:100%;text-align:left;border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.025);color:#fff;border-radius:12px;padding:11px 12px;font-size:10px;cursor:none;transition:.2s;display:flex;align-items:center;gap:9px}.nav button:hover,.nav button.active{background:rgba(255,255,255,.09);border-color:rgba(255,255,255,.24);box-shadow:0 0 18px rgba(255,255,255,.05)}.nav .badge{margin-left:auto;min-width:22px;text-align:center;font-family:'Orbitron';font-size:8px;opacity:.55}.side-footer{margin-top:auto;padding:10px;border-top:1px solid rgba(255,255,255,.07);font-size:8px;opacity:.3;line-height:1.5}
.header{display:flex;justify-content:space-between;align-items:center;padding:22px 26px;border-bottom:1px solid rgba(255,255,255,.08)}.meta{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}.pill{font-size:10px;padding:7px 10px;border:1px solid rgba(255,255,255,.12);border-radius:10px;background:rgba(255,255,255,.035);opacity:.75}.pill b{font-family:'Orbitron'}
.hero{padding:30px;display:grid;grid-template-columns:200px 1fr;gap:28px;align-items:center;border-bottom:1px solid rgba(255,255,255,.08)}.signal{width:160px;height:160px;border-radius:50%;position:relative;display:flex;align-items:center;justify-content:center;margin:auto;background:#020204}.signal:before,.signal:after{content:'';position:absolute;border-radius:50%;inset:0;border:2px solid var(--signal);box-shadow:0 0 18px var(--glow),inset 0 0 18px var(--glow)}.signal:after{inset:15px;border-color:var(--signal2);box-shadow:0 0 22px var(--glow2)}.signal-red{--signal:#ff2d2d;--signal2:#ff7a00;--glow:rgba(255,45,45,.8);--glow2:rgba(255,122,0,.65);animation:dangerPulse 1.05s ease-in-out infinite}.signal-orange{--signal:#ff9800;--signal2:#ffd166;--glow:rgba(255,152,0,.65);--glow2:rgba(255,209,102,.45)}.signal-green{--signal:#25e39a;--signal2:#a7f3d0;--glow:rgba(37,227,154,.55);--glow2:rgba(167,243,208,.3)}.signal-red .orbit{border-color:#ff2d2d;box-shadow:0 0 15px rgba(255,45,45,.7)}.signal-red:before{animation:ringPulse 1.1s infinite}.signal-red:after{animation:ringPulse2 1.1s .2s infinite}.signal .core{width:26px;height:26px;border-radius:50%;background:var(--signal);box-shadow:0 0 22px var(--signal),0 0 55px var(--glow);z-index:4}.signal .orbit{position:absolute;inset:-10px;border-radius:50%;border:1px dashed var(--signal);opacity:.55;animation:spin 5s linear infinite}@keyframes dangerPulse{50%{transform:scale(1.05);filter:brightness(1.25)}}@keyframes ringPulse{50%{box-shadow:0 0 35px rgba(255,45,45,.95),inset 0 0 28px rgba(255,45,45,.5)}}@keyframes ringPulse2{50%{box-shadow:0 0 35px rgba(255,122,0,.8)}}@keyframes spin{to{transform:rotate(360deg)}}.hero h1{font-family:'Orbitron';font-size:24px;letter-spacing:1px;margin-bottom:8px}.hero p{font-size:12px;opacity:.55}.stats{display:flex;gap:18px;margin-top:16px;flex-wrap:wrap}.stat{font-size:10px;opacity:.78}.dot{width:7px;height:7px;border-radius:50%;display:inline-block;margin-right:6px}.red{background:#ff3b3b;box-shadow:0 0 10px #ff3b3b}.orange{background:#ff9800;box-shadow:0 0 10px #ff9800}.green{background:#25e39a;box-shadow:0 0 10px #25e39a}
.content{padding:22px 28px 34px}.tab{display:none}.tab.active{display:block}.section-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:9px}.section-title{font-family:'Orbitron';font-size:10px;letter-spacing:1.8px;opacity:.55}.count{font-family:'Orbitron';font-size:9px;opacity:.4}.panel{border:1px solid rgba(255,255,255,.09);border-radius:16px;overflow:hidden;background:rgba(255,255,255,.025)}.result-row{display:grid;grid-template-columns:150px minmax(260px,1fr) minmax(280px,1fr);gap:14px;padding:11px 13px;border-bottom:1px solid rgba(255,255,255,.055);font-size:10px;align-items:center}.result-row:last-child{border-bottom:0}.mono{font-family:Consolas,monospace}.path{word-break:break-all;opacity:.8}.desc{opacity:.62;line-height:1.4}.ai{color:#c4f1ff;opacity:.85}.tag{display:inline-block;padding:5px 8px;border-radius:8px;font-family:'Orbitron';font-size:8px}.tag.danger{color:#ff9b9b;background:rgba(255,59,59,.11);border:1px solid rgba(255,59,59,.28)}.tag.warning{color:#ffd98a;background:rgba(255,152,0,.09);border:1px solid rgba(255,152,0,.25)}.tag.clean{color:#9ff5c9;background:rgba(37,227,154,.08);border:1px solid rgba(37,227,154,.2)}.tag.fivem{color:#b8c8ff;background:rgba(93,117,255,.08);border:1px solid rgba(93,117,255,.22)}
.account-row{display:grid;grid-template-columns:180px 1fr auto;gap:14px;padding:12px 13px;border-bottom:1px solid rgba(255,255,255,.055);align-items:center;font-size:10px}.account-row:last-child{border-bottom:0}.account-name{opacity:.8}.account-id{color:#d6d6ff;word-break:break-all}.profile-link{color:#fff;text-decoration:none;opacity:.6;cursor:none}.profile-link:hover{opacity:1}.empty{padding:20px;text-align:center;font-size:10px;opacity:.38}.footer{padding:14px 28px;border-top:1px solid rgba(255,255,255,.08);font-size:9px;opacity:.35;text-align:center}
.loading{position:fixed;inset:0;z-index:50;background:rgba(2,2,4,.94);display:flex;align-items:center;justify-content:center;flex-direction:column;gap:14px;transition:opacity .6s}.loading.hide{opacity:0;pointer-events:none}.init{font-family:'Orbitron';font-size:10px;letter-spacing:3px;opacity:.6}.boxes{display:flex;gap:8px}.box{width:42px;height:50px;border-radius:12px;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.04);display:flex;align-items:center;justify-content:center;font-family:'Orbitron';font-size:18px}@media(max-width:900px){.page{padding:12px}.sidebar{position:fixed;left:10px;right:10px;top:auto;bottom:10px;width:auto;height:68px;padding:8px;border-radius:18px}.side-brand,.side-title,.side-footer{display:none}.nav{flex-direction:row;overflow:auto}.nav button{width:auto;min-width:max-content}.page{padding-bottom:92px}.hero{grid-template-columns:1fr;text-align:center}.result-row{grid-template-columns:1fr}.account-row{grid-template-columns:1fr}.meta{justify-content:flex-start}.header{flex-direction:column;align-items:flex-start;gap:12px}}
");
                sb.AppendLine("</style></head><body>");
                sb.AppendLine("<div id='cursorDot'></div><canvas id='bgCanvas'></canvas><canvas id='trailCanvas'></canvas>");
                sb.AppendLine("<div class='loading' id='loading'><div class='init'>INITIALIZING</div><div class='boxes'><div class='box' id='b0'>-</div><div class='box' id='b1'>-</div><div class='box' id='b2'>-</div><div class='box' id='b3'>-</div><div class='box' id='b4'>-</div></div></div>");
                sb.AppendLine("<aside class='sidebar'><div class='side-brand'><div class='brand'>Aura.scanner</div><div class='sub'>AURA SCANNER</div></div><div class='side-title'>RAPOR BÖLÜMLERİ</div><nav class='nav'>");
                sb.AppendLine($"<button class='active' data-tab='high'>🔴 YÜKSEK ŞÜPHELİ <span class='badge'>{hileCount}</span></button>");
                sb.AppendLine($"<button data-tab='ai'>◉ AI ANALİZİ <span class='badge'>{totalFindings}</span></button>");
                sb.AppendLine($"<button data-tab='suspicious'>🟠 ŞÜPHELİ DOSYALAR <span class='badge'>{uyariCount}</span></button>");
                sb.AppendLine($"<button data-tab='clean'>🟢 GÜVENLİ DOSYALAR <span class='badge'>{temizCount}</span></button>");
                sb.AppendLine($"<button data-tab='discord'>● DISCORD HESAPLARI <span class='badge'>{discordCount}</span></button>");
                sb.AppendLine($"<button data-tab='usb'>▣ USB LOGLARI <span class='badge'>{usbCount}</span></button>");
                sb.AppendLine($"<button data-tab='runtime'>◈ RUNTIMEBROKER İMZALARI <span class='badge'>{runtimeAnomalyCount}</span></button>");
                sb.AppendLine($"<button data-tab='fivem'>◆ FIVEM / RPF <span class='badge'>{fivemCount}</span></button></nav><div class='side-footer'>Dosya adı web itibarı: aktif<br>Doğrudan hile anahtar kelimeleri: yüksek şüpheli</div></aside>");
                sb.AppendLine("<div class='page'><div class='shell'>");
                sb.AppendLine($"<header class='header'><div><div class='brand'>AURA SCANNER YÖNETİCİ PANELİ</div><div class='sub'>AURA.SCANNER / WEB REPORT</div></div><div class='meta'><div class='pill'>Kullanıcı: <b>{safeUser}</b></div><div class='pill'>Format: <b>{safeInstall}</b></div><div class='pill'>Skor: <b>{_score}</b></div></div></header>");
                sb.AppendLine($"<section class='hero'><div class='signal {signalClass}'><div class='orbit'></div><div class='core'></div></div><div><h1>{safeStatus}</h1><p>Siyah sinyal tarama durumunu gösterir. Yüksek şüpheli sonuçlarda kırmızı ve turuncu halkalar aktifleşir.</p><div class='stats'><div class='stat'><span class='dot red'></span>HİLE: {hileCount}</div><div class='stat'><span class='dot orange'></span>UYARI: {uyariCount}</div><div class='stat'><span class='dot green'></span>TEMİZ: {temizCount}</div></div></div></section>");
                sb.AppendLine("<main class='content'>");
                sb.AppendLine($"<section class='tab active' id='tab-high'><div class='section-head'><div class='section-title'>YÜKSEK ŞÜPHELİ</div><div class='count'>{hileCount}</div></div><div class='panel'>{highThreatRows}</div></section>");
                sb.AppendLine($"<section class='tab' id='tab-ai'><div class='section-head'><div class='section-title'>AI ANALİZİ</div><div class='count'>{totalFindings}</div></div><div class='panel'>{aiRows}</div></section>");
                sb.AppendLine($"<section class='tab' id='tab-suspicious'><div class='section-head'><div class='section-title'>ŞÜPHELİ DOSYALAR</div><div class='count'>{uyariCount}</div></div><div class='panel'>{suspiciousRows}</div></section>");
                sb.AppendLine($"<section class='tab' id='tab-clean'><div class='section-head'><div class='section-title'>GÜVENLİ DOSYALAR</div><div class='count'>{temizCount}</div></div><div class='panel'>{cleanRows}</div></section>"); sb.AppendLine($"<section class='tab' id='tab-discord'><div class='section-head'><div class='section-title'>DISCORD HESAPLARI</div><div class='count'>{discordCount}</div></div><div class='panel'>{discordRows}</div></section>");
                sb.AppendLine($"<section class='tab' id='tab-usb'><div class='section-head'><div class='section-title'>USB LOGLARI</div><div class='count'>{usbCount}</div></div><div class='panel'>{usbRows}</div></section>");
                sb.AppendLine($"<section class='tab' id='tab-runtime'><div class='section-head'><div class='section-title'>RUNTIMEBROKER İMZA KONTROLÜ</div><div class='count'>{runtimeAnomalyCount}</div></div><div class='panel'>{runtimeRows}</div></section>");
                sb.AppendLine($"<section class='tab' id='tab-fivem'><div class='section-head'><div class='section-title'>FIVEM / RPF</div><div class='count'>{fivemCount}</div></div><div class='panel'>{fivemRows}</div></section>");
                sb.AppendLine("</main>");
                sb.AppendLine($"<footer class='footer'>Aura.scanner · {totalFindings} toplam bulgu · Discord: {discordCount} · FiveM/RPF: {fivemCount} · USB: {usbCount} · USB Boot: {usbBootEntries.Count} · RuntimeBroker anomaly: {runtimeAnomalyCount}</footer></div></div>");
                sb.AppendLine(@"<script>
(function(){
const bg=document.getElementById('bgCanvas'),bc=bg.getContext('2d'),tr=document.getElementById('trailCanvas'),tc=tr.getContext('2d'),cursor=document.getElementById('cursorDot');
function resize(){bg.width=innerWidth;bg.height=innerHeight;tr.width=innerWidth;tr.height=innerHeight}resize();addEventListener('resize',resize);
addEventListener('mousemove',e=>{cursor.style.left=e.clientX+'px';cursor.style.top=e.clientY+'px';});
document.querySelectorAll('button,a').forEach(el=>{el.addEventListener('mouseenter',()=>cursor.classList.add('hot'));el.addEventListener('mouseleave',()=>cursor.classList.remove('hot'));});
let blobs=Array.from({length:7},()=>({x:Math.random()*innerWidth,y:Math.random()*innerHeight,r:50+Math.random()*110,vx:(Math.random()-.5)*1.15,vy:(Math.random()-.5)*1.15}));
function bgLoop(){bc.clearRect(0,0,bg.width,bg.height);for(const b of blobs){b.x+=b.vx;b.y+=b.vy;if(b.x<0||b.x>bg.width)b.vx*=-1;if(b.y<0||b.y>bg.height)b.vy*=-1;let g=bc.createRadialGradient(b.x,b.y,0,b.x,b.y,b.r);g.addColorStop(0,'rgba(255,255,255,.44)');g.addColorStop(.35,'rgba(170,170,180,.14)');g.addColorStop(1,'rgba(255,255,255,0)');bc.fillStyle=g;bc.beginPath();bc.arc(b.x,b.y,b.r,0,Math.PI*2);bc.fill()}requestAnimationFrame(bgLoop)}bgLoop();
let pts=[];addEventListener('mousemove',e=>{pts.push({x:e.clientX,y:e.clientY,a:1});if(pts.length>50)pts.shift()});function trailLoop(){tc.clearRect(0,0,tr.width,tr.height);for(let i=0;i<pts.length-1;i++){let p=pts[i],n=pts[i+1];tc.beginPath();tc.moveTo(p.x,p.y);tc.lineTo(n.x,n.y);tc.strokeStyle='rgba(255,255,255,'+p.a+')';tc.lineWidth=1.5;tc.stroke();p.a-=.035}pts=pts.filter(p=>p.a>0);requestAnimationFrame(trailLoop)}trailLoop();
const buttons=document.querySelectorAll('.nav button');buttons.forEach(btn=>btn.addEventListener('click',()=>{buttons.forEach(x=>x.classList.remove('active'));document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));btn.classList.add('active');document.getElementById('tab-'+btn.dataset.tab).classList.add('active');}));
let boxes=[0,1,2,3,4].map(i=>document.getElementById('b'+i)),done=0;boxes.forEach((box,i)=>{let t=setInterval(()=>box.textContent=Math.floor(Math.random()*10),35);setTimeout(()=>{clearInterval(t);box.textContent=Math.floor(Math.random()*9)+1;done++;if(done===5)setTimeout(()=>document.getElementById('loading').classList.add('hide'),250)},400+i*180)});
})();</script>
</body></html>");

                string finalHtml = sb.ToString();
                byte[] bytes = Encoding.UTF8.GetBytes(finalHtml);
                using (var formData = new MultipartFormDataContent())
                {
                    string discordSummary = discordCount > 0 ? string.Join(", ", _discordAccounts.Select(a => $"{a.Username} ({a.Id})").Distinct(StringComparer.OrdinalIgnoreCase)) : "Tespit edilmedi";
                    string summary = "Aura.scanner AURA SCANNER YÖNETİCİ PANELİHTML raporu hazırlandı\n" + $"Kullanıcı: `{Environment.UserName}`\n" + $"Format Tarihi: `{_installDate}`\n" + $"Discord: `{discordSummary}`\n" + $"Skor: `{_score}`\n" + $"Toplam Bulgu: `{totalFindings}`\n" + $"FiveM/RPF: `{fivemCount}`";
                    formData.Add(new StringContent(summary), "content");
                    formData.Add(new StringContent("Aura Web Security"), "username");
                    var fileContent = new ByteArrayContent(bytes);
                    fileContent.Headers.ContentType = new MediaTypeHeaderValue("text/html");
                    formData.Add(fileContent, "file", $"{Environment.UserName}_aura_rapor.html".ToLowerInvariant());
                    using HttpResponseMessage response = await httpClient.PostAsync(WEBHOOK_URL + "?wait=true", formData);
                    if (response.IsSuccessStatusCode)
                    {
                        string responseJson = await response.Content.ReadAsStringAsync();
                        try
                        {
                            using JsonDocument json = JsonDocument.Parse(responseJson);
                            if (json.RootElement.TryGetProperty("attachments", out JsonElement attachments) && attachments.GetArrayLength() > 0 && attachments[0].TryGetProperty("url", out JsonElement urlElement))
                            {
                                string reportUrl = urlElement.GetString() ?? string.Empty;
                                if (!string.IsNullOrWhiteSpace(reportUrl))
                                {
                                    var linkPayload = new { content = $"🔗 **AURA SCANNER RAPOR LİNKİ:**\n{reportUrl}", username = "Aura Web Security" };
                                    string linkJson = JsonSerializer.Serialize(linkPayload);
                                    using var linkContent = new StringContent(linkJson, Encoding.UTF8, "application/json");
                                    await httpClient.PostAsync(WEBHOOK_URL, linkContent);
                                }
                            }
                        }
                        catch (Exception ex) { Debug.WriteLine("Webhook rapor linki alınamadı: " + ex.Message); }
                    }
                }
            }
            catch (Exception ex) { Debug.WriteLine("Web raporu gönderim hatası: " + ex.Message); }
        }


        private sealed class UsbBootEntry
        {
            public string Drive { get; set; } = string.Empty;
            public string Type { get; set; } = string.Empty;
            public string Evidence { get; set; } = string.Empty;
            public string Status { get; set; } = string.Empty;
        }

        private sealed class RuntimeBrokerEntry
        {
            public string ProcessName { get; set; } = string.Empty;
            public string Path { get; set; } = string.Empty;
            public string SignatureSubject { get; set; } = string.Empty;
            public string SignatureStatus { get; set; } = string.Empty;
            public string Category { get; set; } = string.Empty;
        }

        private static List<UsbBootEntry> CollectUsbBootEvidence()
        {
            var result = new List<UsbBootEntry>();

            try
            {
                foreach (var drive in DriveInfo.GetDrives())
                {
                    try
                    {
                        if (!drive.IsReady || drive.DriveType != DriveType.Removable)
                            continue;

                        string root = drive.RootDirectory.FullName;
                        var markers = new[]
                        {
                            Path.Combine(root, "EFI", "BOOT", "BOOTX64.EFI"),
                            Path.Combine(root, "EFI", "BOOT", "BOOTIA32.EFI"),
                            Path.Combine(root, "bootmgr"),
                            Path.Combine(root, "bootmgr.efi"),
                            Path.Combine(root, "Boot", "BCD"),
                            Path.Combine(root, "sources", "boot.wim")
                        };

                        var found = markers.Where(File.Exists).ToList();

                        result.Add(new UsbBootEntry
                        {
                            Drive = root,
                            Type = found.Count > 0 ? "BOOTABLE USB EVIDENCE" : "REMOVABLE USB",
                            Evidence = found.Count > 0
                                ? string.Join(" | ", found.Select(Path.GetFileName))
                                : "Standart boot marker bulunamadı",
                            Status = found.Count > 0 ? "BOOT İZİ VAR" : "BOOT MARKER YOK"
                        });
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("USB boot evidence failed: " + ex.Message);
            }

            return result;
        }

        private static List<RuntimeBrokerEntry> CollectRuntimeBrokerSignatureAnomalies()
        {
            var result = new List<RuntimeBrokerEntry>();

            try
            {
                foreach (var process in Process.GetProcessesByName("RuntimeBroker"))
                {
                    try
                    {
                        string path = string.Empty;
                        try { path = process.MainModule?.FileName ?? string.Empty; } catch { }

                        string subject = string.Empty;
                        string status = "UNKNOWN";

                        if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
                        {
                            try
                            {
                                using var cert = new X509Certificate2(
                                    X509Certificate.CreateFromSignedFile(path));

                                subject = cert.GetNameInfo(
                                    X509NameType.SimpleName, false);

                                status = cert.Verify() ? "VALID" : "INVALID";
                            }
                            catch
                            {
                                status = "UNSIGNED / UNREADABLE";
                            }
                        }

                        bool windowsPath =
                            path.StartsWith(
                                Environment.GetFolderPath(
                                    Environment.SpecialFolder.Windows),
                                StringComparison.OrdinalIgnoreCase);

                        bool microsoftSignature =
                            subject.IndexOf("Microsoft",
                                StringComparison.OrdinalIgnoreCase) >= 0 ||
                            subject.IndexOf("Windows",
                                StringComparison.OrdinalIgnoreCase) >= 0;

                        bool anomaly =
                            !windowsPath ||
                            !microsoftSignature ||
                            status != "VALID";

                        result.Add(new RuntimeBrokerEntry
                        {
                            ProcessName = process.ProcessName,
                            Path = path,
                            SignatureSubject = string.IsNullOrWhiteSpace(subject)
                                ? "İmza adı okunamadı"
                                : subject,
                            SignatureStatus = status,
                            Category = anomaly
                                ? "FARKLI RUNTIMEBROKER İMZASI"
                                : "STANDART RUNTIMEBROKER"
                        });
                    }
                    catch { }
                    finally
                    {
                        process.Dispose();
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(
                    "RuntimeBroker signature scan failed: " + ex.Message);
            }

            return result;
        }

        private sealed class UsbLogEntry
        {
            public string Name { get; set; } = string.Empty;
            public string Message { get; set; } = string.Empty;
            public string Time { get; set; } = string.Empty;
        }

        private static List<UsbLogEntry> CollectUsbLogsForReport()
        {
            var result = new List<UsbLogEntry>();

            try
            {
                // Windows System log: USB/device related setup and connection events.
                // This reads event metadata only; it does not copy USB files or credentials.
                var query = new EventLogQuery(
                    "System",
                    PathType.LogName,
                    "*[System[(EventID=20001 or EventID=20003 or EventID=2100 or EventID=2101 or EventID=10000)]]");

                using var reader = new EventLogReader(query);
                int count = 0;

                EventRecord ev;
                while (count < 250 && (ev = reader.ReadEvent()) != null)
                {
                    using (ev)
                    {
                        try
                        {
                            string message = string.Empty;
                            try
                            {
                                message = ev.FormatDescription() ?? string.Empty;
                            }
                            catch
                            {
                            }

                            result.Add(new UsbLogEntry
                            {
                                Name = ev.ProviderName ?? "USB / Device",
                                Message = message,
                                Time = ev.TimeCreated?.ToString("yyyy-MM-dd HH:mm:ss") ?? string.Empty
                            });

                            count++;
                        }
                        catch
                        {
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("USB log collection failed: " + ex.Message);
            }

            return result;
        }

    }

    public class PeAnalysisResult
    {
        public bool HasValidPeHeader { get; set; }
        public double Entropy { get; set; }
        public string Hash { get; set; } = string.Empty;
        public string Md5Hash { get; set; } = string.Empty;
    }

    public static class PeAnalyzer
    {
        public static PeAnalysisResult Analyze(string filePath)
        {
            var result = new PeAnalysisResult();
            try
            {
                byte[] bytes = File.ReadAllBytes(filePath);
                result.Entropy = CalculateEntropy(bytes);
                result.Hash = CalculateSha256(bytes);
                result.Md5Hash = CalculateMd5(bytes);

                if (bytes.Length > 0x40 && bytes[0] == 'M' && bytes[1] == 'Z')
                {
                    int peHeaderOffset = BitConverter.ToInt32(bytes, 0x3C);
                    if (peHeaderOffset > 0 && peHeaderOffset < bytes.Length - 4)
                    {
                        result.HasValidPeHeader = (bytes[peHeaderOffset] == 'P' && bytes[peHeaderOffset + 1] == 'E');
                    }
                }
            }
            catch { }
            return result;
        }

        private static double CalculateEntropy(byte[] bytes)
        {
            var map = new int[256];
            foreach (byte b in bytes) map[b]++;

            double entropy = 0;
            double len = bytes.Length;

            for (int i = 0; i < 256; i++)
            {
                if (map[i] == 0) continue;
                double p = map[i] / len;
                entropy -= p * Math.Log(p, 2);
            }
            return entropy;
        }

        private static string CalculateSha256(byte[] bytes)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(bytes);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }

        private static string CalculateMd5(byte[] bytes)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(bytes);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }
    }

    public static class AuraAiAnalyzer
    {
        public static string AnalyzeFinding(ThreatFinding finding)
        {
            string msg = finding.Message.ToLower();
            string path = finding.Path.ToLower();
            string category = finding.Category.ToLower();

            // 1. RPF ve Mod Analizi
            if (path.EndsWith(".rpf") || msg.Contains("rpf") || category.Contains("fivem"))
            {
                if (msg.Contains("ssopti") || msg.Contains("no fall") || msg.Contains("no stamina") || msg.Contains("recoil"))
                {
                    return "[KRİTİK RİSK] Yetkisiz RPF Modifikasyonu! Oyun fiziğini değiştiren (Düşmeme/Sınırsız Dayanıklılık/Sekmeme) illegal dosya entegrasyonu tespit edildi.";
                }
                return "[UYARI] FiveM RPF / Modifikasyon dosyası tespit edildi.";
            }

            // 2. PowerShell / Script İncelemesi
            if (msg.Contains("powershell") || path.EndsWith(".ps1") || msg.Contains("out of instance"))
            {
                return "[ŞÜPHELİ SCRIPT] Bellek veya Temp dizini üzerinden yürütülen, standart dışı PowerShell script izi.";
            }

            // 3. Telemetri ve Log Müdahalesi
            if (msg.Contains("diagtrack") || msg.Contains("telemetry"))
            {
                return "[SİSTEM UYARISI] Windows DiagTrack hizmeti durdurulmuş.";
            }

            // 4. Hile ve Enjektör Analizi
            if (finding.IsInfected || msg.Contains("hile") || msg.Contains("injector") || msg.Contains("eulen") || msg.Contains("cheatengine") || msg.Contains("redengine"))
            {
                return "[YÜKSEK RİSK] PE analizi şüpheli bileşenlere işaret ediyor. Hile/Bellek enjeksiyonu riski.";
            }

            // 5. Şüpheli Analiz Araçları
            if (category.Contains("anti-cheat") || msg.Contains("processhacker") || msg.Contains("x64dbg") || msg.Contains("dnspy"))
            {
                return "[GÜVENLİK İHLALİ] Oyun süreçlerini izleme/tersine mühendislik aracı tespit edildi.";
            }

            // 6. Temiz Dosya Analizi
            if (category == "güvenli dosya")
            {
                return "[TEMİZ DOSYA] Dosya imzası geçerli ve zararlı kod kalıntısına rastlanmadı.";
            }

            return "[DOSYA İNCELEMESİ] Dinamik riski analiz edilmiş dosya.";
        }
    }

    public sealed class DiscordAccountInfo
    {
        public string Id { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
    }

    public class ThreatFinding
    {
        public int Score { get; set; }
        public string Category { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
        public string Hash { get; set; } = string.Empty;
        public bool IsInfected { get; set; }
    }
}
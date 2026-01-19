<?php
// scan.php
// Handles POST from index.php, runs Scanner::scan(), saves JSON + HTML report files, then redirects to report.php?id=...

require_once __DIR__ . "/lib/Scanner.php";

function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

$method = $_SERVER["REQUEST_METHOD"] ?? "GET";
if ($method !== "POST") {
  header("Location: index.php");
  exit;
}

$target = trim($_POST["target"] ?? "");
$mode   = trim($_POST["mode"] ?? "normal");
$timing = trim($_POST["timing"] ?? "T3");

$exportJson = isset($_POST["export_json"]);
$allowNonPrivate = isset($_POST["allow_non_private"]);

if ($target === "") {
  http_response_code(400);
  echo "Missing target CIDR.";
  exit;
}

$reportsDir = __DIR__ . "/reports";
if (!is_dir($reportsDir)) {
  @mkdir($reportsDir, 0775, true);
}

$id = date("Ymd_His") . "_" . substr(bin2hex(random_bytes(6)), 0, 8);

try {
  $data = Scanner::scan($target, $mode, $timing, $allowNonPrivate);

  // Save JSON
  if ($exportJson) {
    $jsonPath = $reportsDir . "/{$id}.json";
    file_put_contents($jsonPath, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
  }

  // Save HTML report snapshot (optional but nice for “Export HTML”)
  $htmlPath = $reportsDir . "/{$id}.html";
  file_put_contents($htmlPath, buildHtmlReport($data, $id));

  // Redirect to viewer
  header("Location: report.php?id=" . urlencode($id));
  exit;

} catch (Throwable $e) {
  // Render a nice error page
  $msg = $e->getMessage();
  ?>
  <!doctype html>
  <html lang="en">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>Scan Failed</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&display=swap" rel="stylesheet">
    <style>
      :root{
        --bg:#07101a; --bg2:#050b12;
        --line: rgba(255,255,255,.10);
        --text: rgba(255,255,255,.92);
        --muted: rgba(255,255,255,.68);
        --brand:#2f8cff;
      }
      *{box-sizing:border-box}
      body{
        margin:0; font-family:Inter,system-ui,Segoe UI,Roboto,Arial;
        color:var(--text);
        background: radial-gradient(1200px 600px at 30% 15%, rgba(47,140,255,.22), transparent 55%),
                    radial-gradient(900px 500px at 80% 20%, rgba(31,182,255,.18), transparent 55%),
                    linear-gradient(180deg, var(--bg), var(--bg2));
      }
      .wrap{ max-width: 920px; margin: 0 auto; padding: 28px 18px; }
      .card{
        border:1px solid var(--line);
        background: rgba(255,255,255,.05);
        border-radius: 18px;
        padding: 16px;
      }
      .title{ font-weight: 900; font-size: 22px; margin:0 0 6px; }
      .sub{ color: var(--muted); margin:0 0 12px; line-height:1.6; }
      pre{
        white-space: pre-wrap;
        background: rgba(0,0,0,.35);
        border: 1px solid rgba(255,255,255,.10);
        border-radius: 14px;
        padding: 12px;
        color: rgba(255,255,255,.88);
        overflow:auto;
      }
      a{
        display:inline-flex; margin-top: 12px;
        text-decoration:none; font-weight: 900;
        color: var(--text);
        border:1px solid rgba(255,255,255,.12);
        background: rgba(255,255,255,.06);
        padding: 10px 14px; border-radius: 999px;
      }
      a:hover{ border-color: rgba(47,140,255,.45); }
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="card">
        <h1 class="title">Scan Failed</h1>
        <p class="sub">Fix the issue below, then run the scan again.</p>
        <pre><?=h($msg)?></pre>
        <a href="index.php">← Back to scanner</a>
      </div>
    </div>
  </body>
  </html>
  <?php
  exit;
}

/* ---------------------------
 * HTML Report Builder (saved snapshot)
 * --------------------------- */
function buildHtmlReport(array $data, string $id): string {
  $meta = $data["meta"] ?? [];
  $summary = $data["summary"] ?? [];
  $hosts = $data["hosts"] ?? [];

  $target = htmlspecialchars($meta["target"] ?? "—", ENT_QUOTES, "UTF-8");
  $ts = htmlspecialchars($meta["timestamp"] ?? "—", ENT_QUOTES, "UTF-8");
  $mode = htmlspecialchars($meta["mode"] ?? "—", ENT_QUOTES, "UTF-8");
  $timing = htmlspecialchars($meta["timing"] ?? "—", ENT_QUOTES, "UTF-8");

  $alive = (int)($summary["alive_hosts"] ?? 0);
  $openTotal = (int)($summary["open_ports_total"] ?? 0);
  $riskFind = (int)($summary["risk_findings"] ?? 0);

  $rows = "";
  foreach ($hosts as $h) {
    $ip = htmlspecialchars($h["ip"] ?? "", ENT_QUOTES, "UTF-8");
    $hn = htmlspecialchars($h["hostname"] ?? "—", ENT_QUOTES, "UTF-8");
    $ports = $h["ports"] ?? [];
    $flags = $h["risk_flags"] ?? [];

    $portList = "";
    foreach ($ports as $p) {
      $pno = (int)($p["port"] ?? 0);
      $svc = htmlspecialchars($p["service"] ?? "", ENT_QUOTES, "UTF-8");
      $portList .= "<span class='tag'>{$pno}<em>{$svc}</em></span>";
    }
    if ($portList === "") $portList = "<span class='muted'>No open ports found</span>";

    $flagList = "";
    foreach ($flags as $f) {
      $sev = htmlspecialchars($f["severity"] ?? "info", ENT_QUOTES, "UTF-8");
      $msg = htmlspecialchars($f["message"] ?? "", ENT_QUOTES, "UTF-8");
      $flagList .= "<div class='flag {$sev}'><b>".strtoupper($sev)."</b><span>{$msg}</span></div>";
    }
    if ($flagList === "") $flagList = "<span class='muted'>No risk flags</span>";

    $rows .= "
      <div class='host'>
        <div class='host-top'>
          <div class='host-title'>{$ip} <span class='hn'>{$hn}</span></div>
          <div class='host-badges'>
            <span class='pill'>Open ports: <b>".count($ports)."</b></span>
            <span class='pill'>Risk flags: <b>".count($flags)."</b></span>
          </div>
        </div>
        <div class='block'>
          <div class='block-title'>Open Ports</div>
          <div class='tags'>{$portList}</div>
        </div>
        <div class='block'>
          <div class='block-title'>Risk Findings</div>
          <div class='flags'>{$flagList}</div>
        </div>
      </div>
    ";
  }

  return "<!doctype html>
  <html lang='en'>
  <head>
    <meta charset='utf-8'/>
    <meta name='viewport' content='width=device-width, initial-scale=1'/>
    <title>Report {$id}</title>
    <link rel='preconnect' href='https://fonts.googleapis.com'>
    <link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>
    <link href='https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&display=swap' rel='stylesheet'>
    <style>
      :root{
        --bg:#07101a; --bg2:#050b12;
        --line: rgba(255,255,255,.10);
        --text: rgba(255,255,255,.92);
        --muted: rgba(255,255,255,.68);
        --brand:#2f8cff; --brand2:#1fb6ff;
      }
      *{box-sizing:border-box}
      body{
        margin:0; font-family:Inter,system-ui,Segoe UI,Roboto,Arial;
        color:var(--text);
        background:
          radial-gradient(1200px 600px at 30% 15%, rgba(47,140,255,.22), transparent 55%),
          radial-gradient(900px 500px at 80% 20%, rgba(31,182,255,.18), transparent 55%),
          linear-gradient(180deg, var(--bg), var(--bg2));
      }
      .wrap{ max-width: 1120px; margin:0 auto; padding: 22px 18px 30px; }
      .top{
        display:flex; justify-content:space-between; align-items:flex-end; gap: 12px;
        border-bottom: 1px solid rgba(255,255,255,.08);
        padding-bottom: 14px;
      }
      .title{ margin:0; font-weight: 900; letter-spacing:.2px; font-size: 22px; }
      .sub{ margin:6px 0 0; color: var(--muted); font-size: 13px; line-height:1.5; }
      .btns{ display:flex; gap:10px; flex-wrap:wrap; }
      .btn{
        text-decoration:none; color:var(--text); font-weight:900; font-size: 13px;
        border:1px solid rgba(255,255,255,.12);
        background: rgba(255,255,255,.06);
        padding: 10px 14px; border-radius: 999px;
      }
      .btn.primary{
        border-color: rgba(47,140,255,.45);
        background: linear-gradient(135deg, rgba(47,140,255,.95), rgba(31,182,255,.9));
      }
      .grid{
        display:grid; grid-template-columns: repeat(3,minmax(0,1fr));
        gap: 12px; margin-top: 14px;
      }
      .stat{
        border:1px solid rgba(255,255,255,.10);
        background: rgba(255,255,255,.04);
        border-radius: 18px; padding: 14px;
      }
      .stat b{ display:block; font-size: 22px; }
      .stat span{ color: var(--muted); font-size: 12px; }
      .hosts{ margin-top: 14px; display:flex; flex-direction:column; gap: 12px; }
      .host{
        border:1px solid rgba(255,255,255,.10);
        background: rgba(255,255,255,.04);
        border-radius: 18px;
        padding: 14px;
      }
      .host-top{
        display:flex; justify-content:space-between; align-items:center; gap: 10px; flex-wrap:wrap;
      }
      .host-title{ font-weight: 900; }
      .hn{ color: var(--muted); font-weight: 700; margin-left: 10px; }
      .host-badges{ display:flex; gap: 8px; flex-wrap:wrap; }
      .pill{
        padding: 8px 10px; border-radius: 999px;
        border:1px solid rgba(255,255,255,.10);
        background: rgba(255,255,255,.05);
        color: rgba(255,255,255,.82);
        font-weight: 800; font-size: 12px;
      }
      .pill b{ color: var(--text); }
      .block{ margin-top: 12px; }
      .block-title{ font-weight: 900; font-size: 12px; letter-spacing:.12em; text-transform: uppercase; color: rgba(255,255,255,.80); margin-bottom: 8px; }
      .tags{ display:flex; gap: 8px; flex-wrap:wrap; }
      .tag{
        display:inline-flex; align-items:center; gap: 8px;
        border:1px solid rgba(255,255,255,.10);
        background: rgba(255,255,255,.05);
        border-radius: 999px;
        padding: 7px 10px;
        font-weight: 800;
        font-size: 12px;
      }
      .tag em{ font-style:normal; color: var(--muted); font-weight: 800; }
      .flags{ display:flex; flex-direction:column; gap: 8px; }
      .flag{
        border:1px solid rgba(255,255,255,.10);
        background: rgba(0,0,0,.20);
        border-radius: 14px;
        padding: 10px 12px;
        display:flex; gap: 10px;
      }
      .flag b{ width: 80px; }
      .flag.critical{ border-color: rgba(255,80,80,.35); }
      .flag.high{ border-color: rgba(255,165,0,.35); }
      .flag.medium{ border-color: rgba(255,214,0,.28); }
      .flag.low{ border-color: rgba(31,182,255,.25); }
      .muted{ color: var(--muted); }
      @media (max-width: 980px){ .grid{ grid-template-columns: 1fr; } }
    </style>
  </head>
  <body>
    <div class='wrap'>
      <div class='top'>
        <div>
          <h1 class='title'>Security Report</h1>
          <div class='sub'>
            Target: <b>{$target}</b> • Time: <b>{$ts}</b> • Mode: <b>{$mode}</b> • Timing: <b>{$timing}</b>
          </div>
        </div>
        <div class='btns'>
          <a class='btn' href='../index.php'>← New Scan</a>
          <a class='btn primary' href='{$id}.json' download>Download JSON</a>
        </div>
      </div>

      <div class='grid'>
        <div class='stat'><b>{$alive}</b><span>Alive Hosts</span></div>
        <div class='stat'><b>{$openTotal}</b><span>Total Open Ports</span></div>
        <div class='stat'><b>{$riskFind}</b><span>Risk Findings</span></div>
      </div>

      <div class='hosts'>
        {$rows}
      </div>
    </div>
  </body>
  </html>";
}

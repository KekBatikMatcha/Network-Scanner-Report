<?php
// report.php
// Displays a saved report by id (reads reports/{id}.json). Also links to exported HTML snapshot if you want.

function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

$id = preg_replace('~[^a-zA-Z0-9_\-]~', '', $_GET["id"] ?? "");
if ($id === "") {
  header("Location: index.php");
  exit;
}

$reportsDir = __DIR__ . "/reports";
$jsonPath = $reportsDir . "/{$id}.json";
$htmlSnapshot = $reportsDir . "/{$id}.html";

if (!file_exists($jsonPath)) {
  http_response_code(404);
  echo "Report not found: " . h($id);
  exit;
}

$data = json_decode(file_get_contents($jsonPath), true);
if (!is_array($data)) {
  http_response_code(500);
  echo "Invalid report JSON.";
  exit;
}

$meta = $data["meta"] ?? [];
$summary = $data["summary"] ?? [];
$hosts = $data["hosts"] ?? [];

$target = $meta["target"] ?? "—";
$ts = $meta["timestamp"] ?? "—";
$mode = $meta["mode"] ?? "—";
$timing = $meta["timing"] ?? "—";

$alive = (int)($summary["alive_hosts"] ?? 0);
$openTotal = (int)($summary["open_ports_total"] ?? 0);
$riskFind = (int)($summary["risk_findings"] ?? 0);

?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Report | <?=h($target)?></title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&display=swap" rel="stylesheet">
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

    details{
      margin-top: 10px;
      border:1px solid rgba(255,255,255,.08);
      border-radius: 14px;
      background: rgba(0,0,0,.18);
      padding: 10px 12px;
    }
    summary{
      cursor:pointer;
      font-weight: 900;
      color: rgba(255,255,255,.85);
      list-style:none;
    }
    summary::-webkit-details-marker{ display:none; }
    pre{
      white-space: pre-wrap;
      word-break: break-word;
      color: rgba(255,255,255,.86);
      margin: 10px 0 0;
      font-size: 12px;
    }

    @media (max-width: 980px){ .grid{ grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div>
        <h1 class="title">Security Report</h1>
        <div class="sub">
          Target: <b><?=h($target)?></b> • Time: <b><?=h($ts)?></b> • Mode: <b><?=h($mode)?></b> • Timing: <b><?=h($timing)?></b>
        </div>
      </div>
      <div class="btns">
        <a class="btn" href="index.php">← New Scan</a>
        <a class="btn primary" href="<?=h("reports/{$id}.json")?>" download>Download JSON</a>
        <?php if (file_exists($htmlSnapshot)): ?>
          <a class="btn" href="<?=h("reports/{$id}.html")?>" target="_blank" rel="noreferrer">Open HTML Export</a>
        <?php endif; ?>
      </div>
    </div>

    <div class="grid">
      <div class="stat"><b><?=h($alive)?></b><span>Alive Hosts</span></div>
      <div class="stat"><b><?=h($openTotal)?></b><span>Total Open Ports</span></div>
      <div class="stat"><b><?=h($riskFind)?></b><span>Risk Findings</span></div>
    </div>

    <div class="hosts">
      <?php foreach($hosts as $h):
        $ip = $h["ip"] ?? "";
        $hn = $h["hostname"] ?? "—";
        $ports = $h["ports"] ?? [];
        $flags = $h["risk_flags"] ?? [];
      ?>
        <div class="host">
          <div class="host-top">
            <div class="host-title">
              <?=h($ip)?> <span class="hn"><?=h($hn)?></span>
            </div>
            <div class="host-badges">
              <span class="pill">Open ports: <b><?=count($ports)?></b></span>
              <span class="pill">Risk flags: <b><?=count($flags)?></b></span>
            </div>
          </div>

          <div class="block">
            <div class="block-title">Open Ports</div>
            <div class="tags">
              <?php if(empty($ports)): ?>
                <span class="muted">No open ports found</span>
              <?php else: ?>
                <?php foreach($ports as $p):
                  $pno = (int)($p["port"] ?? 0);
                  $svc = $p["service"] ?? "";
                  $ver = trim($p["version"] ?? "");
                ?>
                  <span class="tag">
                    <?=h($pno)?><em><?=h($svc)?></em>
                    <?php if($ver !== ""): ?>
                      <em style="opacity:.85">• <?=h($ver)?></em>
                    <?php endif; ?>
                  </span>
                <?php endforeach; ?>
              <?php endif; ?>
            </div>
          </div>

          <div class="block">
            <div class="block-title">Risk Findings</div>
            <div class="flags">
              <?php if(empty($flags)): ?>
                <span class="muted">No risk flags</span>
              <?php else: ?>
                <?php foreach($flags as $f):
                  $sev = $f["severity"] ?? "info";
                  $msg = $f["message"] ?? "";
                ?>
                  <div class="flag <?=h($sev)?>">
                    <b><?=h(strtoupper($sev))?></b>
                    <span><?=h($msg)?></span>
                  </div>
                <?php endforeach; ?>
              <?php endif; ?>
            </div>
          </div>
        </div>
      <?php endforeach; ?>
    </div>

    <details>
      <summary>Show raw discovery output (debug)</summary>
      <pre><?=h($data["raw"]["discover_output"] ?? "")?></pre>
    </details>
  </div>
</body>
</html>

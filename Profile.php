<?php
// lib/Profile.php

class Profile {

  // ---------- HOST PROFILING ----------
  public static function classify(array $ports): array {
    // ports: [ ["port"=>22,"service"=>"ssh"], ... ]
    $p = self::portSet($ports);

    // Strong signals
    if (isset($p[3389]) || isset($p[5900]) || isset($p[445]) || isset($p[139])) {
      // RDP/VNC/SMB often on workstations or file servers
      if (isset($p[445]) || isset($p[139])) return ["type" => "Server", "confidence" => "Medium"];
      return ["type" => "Workstation", "confidence" => "Medium"];
    }

    if (isset($p[80]) || isset($p[443]) || isset($p[8080]) || isset($p[8443])) {
      // Web services usually server / device UI
      if (isset($p[22]) || isset($p[3306]) || isset($p[5432])) return ["type" => "Server", "confidence" => "High"];
      return ["type" => "Network Device", "confidence" => "Medium"];
    }

    if (isset($p[9100]) || isset($p[515]) || isset($p[631])) {
      return ["type" => "Printer / IoT", "confidence" => "High"];
    }

    if (isset($p[53]) || isset($p[67]) || isset($p[68])) {
      return ["type" => "Network Device", "confidence" => "Medium"];
    }

    if (isset($p[22]) && count($ports) <= 2) {
      return ["type" => "Server", "confidence" => "Low"];
    }

    if (empty($ports)) {
      return ["type" => "Workstation / Mobile (Hardened)", "confidence" => "Medium"];
    }

    return ["type" => "Unknown", "confidence" => "Low"];
  }

  private static function portSet(array $ports): array {
    $set = [];
    foreach ($ports as $pt) {
      $set[(int)($pt["port"] ?? 0)] = true;
    }
    return $set;
  }

  // ---------- SECURITY SCORE ----------
  public static function computeScore(array $ports, array $riskFlags): array {
    $score = 100;

    // 1) open ports penalty
    $openCount = count($ports);
    $score -= min(30, $openCount * 3); // up to -30

    // 2) severity penalty
    foreach ($riskFlags as $f) {
      $sev = strtolower($f["severity"] ?? "low");
      if ($sev === "critical") $score -= 25;
      elseif ($sev === "high") $score -= 18;
      elseif ($sev === "medium") $score -= 10;
      elseif ($sev === "low") $score -= 6;
      else $score -= 3;
    }

    // 3) risky ports penalty (extra)
    $dangerPorts = [23=>12, 21=>10, 445=>8, 139=>8, 3389=>8, 5900=>7, 80=>5];
    foreach ($ports as $pt) {
      $p = (int)($pt["port"] ?? 0);
      if (isset($dangerPorts[$p])) $score -= $dangerPorts[$p];
    }

    $score = max(0, min(100, $score));

    // Grade
    $grade = self::grade($score);

    return [
      "score" => $score,
      "grade" => $grade["label"],
      "grade_key" => $grade["key"], // excellent/good/moderate/poor
      "explanation" => [
        "open_ports" => $openCount,
        "risk_flags" => count($riskFlags)
      ]
    ];
  }

  private static function grade(int $score): array {
    if ($score >= 90) return ["key"=>"excellent","label"=>"Excellent"];
    if ($score >= 75) return ["key"=>"good","label"=>"Good"];
    if ($score >= 55) return ["key"=>"moderate","label"=>"Moderate"];
    return ["key"=>"poor","label"=>"Poor"];
  }
}

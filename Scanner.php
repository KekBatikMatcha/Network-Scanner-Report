<?php
// lib/Scanner.php
// Cross-platform (Windows/Linux) Nmap scanner for: host discovery + top ports scan + optional service detection
// Outputs structured array you can save as JSON and render in report.php

require_once __DIR__ . "/Risk.php";
require_once __DIR__ . "/Profile.php";


class Scanner
{
  /* ---------------------------
   *  Safety / Validation
   * --------------------------- */

  public static function isPrivateCidr(string $cidr): bool
  {
    // Format: A.B.C.D/NN
    if (!preg_match('~^(\d{1,3}\.){3}\d{1,3}\/(\d{1,2})$~', $cidr)) return false;

    [$ip, $mask] = explode("/", $cidr, 2);
    $mask = (int)$mask;

    if ($mask < 8 || $mask > 30) return false;
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return false;

    $long = ip2long($ip);
    if ($long === false) return false;

    // RFC1918 ranges:
    // 10.0.0.0/8
    if (($long & ip2long("255.0.0.0")) === ip2long("10.0.0.0")) return true;
    // 172.16.0.0/12
    if (($long & ip2long("255.240.0.0")) === ip2long("172.16.0.0")) return true;
    // 192.168.0.0/16
    if (($long & ip2long("255.255.0.0")) === ip2long("192.168.0.0")) return true;

    return false;
  }

  public static function normalizeTiming(?string $timing): string
  {
    $timing = strtoupper(trim((string)$timing));
    return in_array($timing, ["T2", "T3", "T4"], true) ? $timing : "T3";
  }

  public static function normalizeMode(?string $mode): string
  {
    $mode = strtolower(trim((string)$mode));
    return in_array($mode, ["quick", "normal", "deep"], true) ? $mode : "normal";
  }

  /* ---------------------------
   *  Nmap checks (Windows/Linux)
   * --------------------------- */

  public static function nmapExists(): bool
  {
    $out = [];
    $code = 0;

    if (self::isWindows()) {
      @exec("where nmap 2>NUL", $out, $code);
    } else {
      @exec("command -v nmap 2>/dev/null", $out, $code);
    }

    return $code === 0 && !empty($out);
  }

  private static function isWindows(): bool
  {
    return stripos(PHP_OS, 'WIN') === 0;
  }

  /* ---------------------------
   *  Main Scan
   * --------------------------- */

  /**
   * @param string $target CIDR (e.g. 192.168.1.0/24)
   * @param string $mode quick|normal|deep
   * @param string $timing T2|T3|T4
   * @param bool $allowNonPrivate If false, blocks non-RFC1918 CIDRs
   * @return array structured scan result
   */
  public static function scan(
    string $target,
    string $mode = "normal",
    string $timing = "T3",
    bool $allowNonPrivate = false
  ): array {
    $target = trim($target);
    $mode = self::normalizeMode($mode);
    $timing = self::normalizeTiming($timing);

    if (!$allowNonPrivate && !self::isPrivateCidr($target)) {
      throw new RuntimeException("Blocked: target must be a private RFC1918 CIDR (e.g., 192.168.x.x/24).");
    }

    if (!self::nmapExists()) {
      throw new RuntimeException("nmap is not installed or not available in PATH.");
    }

    // Settings
    $topPorts = ($mode === "quick") ? 50 : 100;
    $serviceDetect = ($mode === "deep");

    // 1) Host discovery
    // -sn: host discovery only
    // -PS/-PA: TCP SYN/ACK probes (works even when ICMP blocked sometimes)
    $discoverCmd = "nmap -sn -{$timing} -PS80,443,22 -PA80,443 " . escapeshellarg($target);
    $discoverText = self::run($discoverCmd);

    $hosts = self::parseDiscover($discoverText); // list of IPs

    // 2) Port scan each host
    $results = [];
    $openPortsTotal = 0;
    $riskFindings = 0;

    foreach ($hosts as $ip) {
      $scanCmd = "nmap -{$timing} --top-ports {$topPorts} " . ($serviceDetect ? "-sV " : "") . escapeshellarg($ip);
      $scanText = self::run($scanCmd);

      $parsed = self::parsePorts($scanText, $serviceDetect);
      $openPortsTotal += count($parsed["ports"]);

      // Risk flags
      $flags = [];
      foreach ($parsed["ports"] as $p) {
        $flag = Risk::flagForPort((int)$p["port"]);
        if ($flag) {
          $flags[] = [
            "severity" => $flag[0],
            "message"  => $flag[1],
            "port"     => (int)$p["port"],
            "service"  => $p["service"] ?? "",
          ];
        }
      }

      $riskFindings += count($flags);

      // Sort flags by severity
      usort($flags, function ($a, $b) {
        return Risk::severityWeight($b["severity"]) <=> Risk::severityWeight($a["severity"]);
      });

      $results[] = [
        "ip"         => $ip,
        "hostname"   => $parsed["hostname"],
        "ports"      => $parsed["ports"],
        "risk_flags" => $flags,
      ];
    }

    // Sort hosts by risk count desc, then open ports desc
    usort($results, function ($a, $b) {
      $ra = count($a["risk_flags"]);
      $rb = count($b["risk_flags"]);
      if ($ra !== $rb) return $rb <=> $ra;
      return count($b["ports"]) <=> count($a["ports"]);
    });

    return [
      "meta" => [
        "target" => $target,
        "timestamp" => date("Y-m-d H:i:s"),
        "tool" => "nmap",
        "mode" => $mode,
        "timing" => $timing,
        "top_ports" => $topPorts,
        "service_detection" => $serviceDetect,
        "notes" => "Use only on authorized networks.",
      ],
      "summary" => [
        "alive_hosts" => count($hosts),
        "open_ports_total" => $openPortsTotal,
        "risk_findings" => $riskFindings,
      ],
      "hosts" => $results,
      "raw" => [
        "discover_cmd" => $discoverCmd,
        "discover_output" => $discoverText,
      ],
    ];
  }

  /* ---------------------------
   *  Command Runner
   * --------------------------- */

  private static function run(string $cmd): string
  {
    $out = [];
    $code = 0;

    // Redirect stderr to stdout cross-platform
    if (self::isWindows()) {
      @exec($cmd . " 2>&1", $out, $code);
    } else {
      @exec($cmd . " 2>&1", $out, $code);
    }

    $txt = implode("\n", $out);

    // Nmap sometimes returns non-zero for partial failures; still handle gracefully:
    // But if output is empty, treat as failure.
    if ($code !== 0 && trim($txt) === "") {
      throw new RuntimeException("Command failed: {$cmd}");
    }

    return $txt;
  }

  /* ---------------------------
   *  Parsers
   * --------------------------- */

  private static function parseDiscover(string $txt): array
  {
    // Finds:
    // "Nmap scan report for 192.168.1.10"
    // "Nmap scan report for host (192.168.1.10)"
    $ips = [];

    // With hostname (host (ip))
    if (preg_match_all('~Nmap scan report for\s+[^\(]+\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)~', $txt, $m)) {
      $ips = array_merge($ips, $m[1] ?? []);
    }

    // Without hostname
    if (preg_match_all('~Nmap scan report for\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)~', $txt, $m2)) {
      $ips = array_merge($ips, $m2[1] ?? []);
    }

    $ips = array_values(array_unique($ips));
    sort($ips, SORT_NATURAL);

    return $ips;
  }

  private static function parsePorts(string $txt, bool $serviceDetect): array
  {
    $hostname = null;

    // "Nmap scan report for HOST (IP)"
    if (preg_match('~Nmap scan report for\s+([^\s]+)\s+\(([0-9.]+)\)~', $txt, $m)) {
      $hostname = $m[1];
    }

    $ports = [];
    $lines = preg_split("/\r\n|\n|\r/", $txt);

    foreach ($lines as $line) {
      $line = trim($line);

      // Typical:
      // "22/tcp open  ssh"
      // Deep:
      // "22/tcp open  ssh  OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)"
      if (preg_match('~^(\d+)\/tcp\s+open\s+([a-zA-Z0-9\-\_\.]+)(.*)$~', $line, $m)) {
        $port = (int)$m[1];
        $service = $m[2];
        $ver = trim($m[3] ?? "");

        $ports[] = [
          "port" => $port,
          "proto" => "tcp",
          "state" => "open",
          "service" => $service,
          "version" => $serviceDetect ? $ver : "",
        ];
      }
    }

    // Sort ports ascending
    usort($ports, fn($a, $b) => $a["port"] <=> $b["port"]);

    return [
      "hostname" => $hostname,
      "ports" => $ports,
    ];
  }
}

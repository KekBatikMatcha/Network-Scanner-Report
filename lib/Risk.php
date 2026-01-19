<?php
// lib/Risk.php
class Risk {
  public static function flagForPort(int $port): ?array {
    $map = [
      21 => ["high", "FTP open (21) — insecure plaintext auth possible."],
      22 => ["info", "SSH open (22) — ensure strong passwords/keys, disable root login."],
      23 => ["critical", "Telnet open (23) — plaintext remote access (high risk)."],
      25 => ["info", "SMTP open (25) — ensure anti-spam, TLS, and auth controls."],
      53 => ["info", "DNS open (53) — check recursion exposure and DNSSEC."],
      80 => ["info", "HTTP open (80) — consider HTTPS and secure headers."],
      110 => ["high", "POP3 open (110) — plaintext possible; prefer TLS."],
      139 => ["high", "SMB/NetBIOS (139) — legacy file sharing exposure."],
      143 => ["info", "IMAP open (143) — prefer TLS and secure auth."],
      443 => ["low", "HTTPS open (443) — check TLS config and certs."],
      445 => ["critical", "SMB (445) — common lateral movement target; restrict access."],
      3389 => ["high", "RDP (3389) — brute-force target; restrict + MFA + VPN."],
      5900 => ["high", "VNC (5900) — restrict access; use strong auth."],
    ];
    return $map[$port] ?? null;
  }

  public static function severityWeight(string $sev): int {
    return match($sev){
      'critical' => 4,
      'high' => 3,
      'medium' => 2,
      'low' => 1,
      default => 0
    };
  }
}

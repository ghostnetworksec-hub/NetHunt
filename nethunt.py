#!/usr/bin/env python3
"""
NetHunt — Automated Network VAPT CLI Tool
Covers: Port scanning, service enum, sniffing, firewall/ACL testing

Requirements: pip3 install rich
Tools:        brew install nmap masscan tcpdump netcat

Usage:
    sudo python3 nethunt.py -t 192.168.1.1 --all
    sudo python3 nethunt.py -t 192.168.1.1 --ports
    sudo python3 nethunt.py -t 192.168.1.1 --firewall
    sudo python3 nethunt.py --iface en0    --sniff --duration 30
"""

import argparse
import subprocess
import sys
import os
import re
import json
import datetime
import socket
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.rule import Rule
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None
    print("[!] Tip: pip3 install rich  for better output")

OUTPUT_DIR = Path("nethunt_output")

BANNER = r"""
  _   _      _   _   _             _   
 | \ | | ___| |_| | | |_   _ _ __ | |_ 
 |  \| |/ _ \ __| |_| | | | | '_ \| __|
 | |\  |  __/ |_|  _  | |_| | | | | |_ 
 |_| \_|\___|\__|_| |_|\__,_|_| |_|\__|
                                        
  Automated Network VAPT CLI
  Port Scan · Sniff · Firewall Test
"""

SERVICE_VULNS = {
    "ftp":           ["Anonymous login possible",        "Cleartext credentials",         "FTP Bounce attack"],
    "ssh":           ["Weak ciphers may be accepted",    "Version disclosure",             "Brute force risk"],
    "telnet":        ["CLEARTEXT PROTOCOL — CRITICAL",   "Immediate replacement with SSH required"],
    "smtp":          ["Open relay check needed",         "User enumeration (VRFY/EXPN)",   "Cleartext auth"],
    "dns":           ["Zone transfer possible",          "DNS amplification risk",         "Cache poisoning"],
    "http":          ["Unencrypted traffic",             "Directory traversal",            "Default pages exposed"],
    "https":         ["SSL/TLS misconfiguration",        "Weak ciphers",                   "Cert validation"],
    "smb":           ["EternalBlue (MS17-010)",          "Null session possible",          "SMB signing disabled"],
    "microsoft-ds":  ["EternalBlue (MS17-010)",          "Null session possible",          "SMB signing disabled"],
    "rdp":           ["BlueKeep vulnerability",          "Weak authentication",            "NLA may be disabled"],
    "ms-wbt-server": ["BlueKeep vulnerability",          "Weak authentication"],
    "mysql":         ["Remote root login",               "No auth required",               "Version disclosure"],
    "ms-sql":        ["SA account default password",     "xp_cmdshell may be enabled"],
    "vnc":           ["No authentication possible",      "Weak password",                  "Cleartext session"],
    "snmp":          ["Default community strings",       "SNMPv1/v2 cleartext",            "Info disclosure"],
    "ldap":          ["Null bind possible",              "Anonymous queries",              "Cleartext credentials"],
    "nfs":           ["World-readable exports",          "No auth required"],
    "redis":         ["No authentication by default",    "Remote code execution risk"],
    "mongodb":       ["No authentication by default",    "Data exposure"],
    "elasticsearch": ["No auth — data exposure",         "Remote code execution"],
    "rpcbind":       ["Portmapper info leak",            "RPC services exposed"],
}

RISKY_PORTS = {
    "21":    ("FTP",           "CRITICAL"),
    "23":    ("Telnet",        "CRITICAL"),
    "25":    ("SMTP",          "HIGH"),
    "111":   ("RPC Portmap",   "HIGH"),
    "135":   ("MS-RPC",        "HIGH"),
    "139":   ("NetBIOS",       "HIGH"),
    "445":   ("SMB",           "CRITICAL"),
    "1433":  ("MSSQL",         "CRITICAL"),
    "3306":  ("MySQL",         "CRITICAL"),
    "3389":  ("RDP",           "CRITICAL"),
    "5432":  ("PostgreSQL",    "HIGH"),
    "5900":  ("VNC",           "CRITICAL"),
    "6379":  ("Redis",         "CRITICAL"),
    "9200":  ("Elasticsearch", "CRITICAL"),
    "27017": ("MongoDB",       "CRITICAL"),
}

EVASION_TECHNIQUES = [
    ("SYN scan",           "-sS"),
    ("NULL scan",          "-sN"),
    ("FIN scan",           "-sF"),
    ("XMAS scan",          "-sX"),
    ("ACK scan",           "-sA"),
    ("Fragmented packets", "-f --mtu 8"),
]


# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def print_banner():
    if RICH:
        console.print(Panel(BANNER, style="bold cyan", border_style="cyan"))
    else:
        print(BANNER)

def info(m):
    (console.print(f"[cyan]→[/cyan]  {m}") if RICH else print(f"[.] {m}"))

def success(m):
    (console.print(f"[bold green]✔[/bold green]  {m}") if RICH else print(f"[+] {m}"))

def warn(m):
    (console.print(f"[yellow]⚠[/yellow]  {m}") if RICH else print(f"[!] {m}"))

def error(m):
    (console.print(f"[bold red]✘[/bold red]  {m}") if RICH else print(f"[-] {m}"))

def section(t):
    if RICH:
        console.print(Rule(f"[bold white] {t} [/bold white]", style="dim cyan"))
    else:
        print(f"\n{'='*60}\n  {t}\n{'='*60}")

def run_cmd(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "Timed out", 1
    except Exception as e:
        return "", str(e), 1

def tool_exists(t):
    _, _, rc = run_cmd(f"which {t}")
    return rc == 0

def is_root():
    return os.geteuid() == 0

def save(out_dir, filename, content):
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / filename
    with open(p, "w") as f:
        f.write(content if isinstance(content, str) else json.dumps(content, indent=2))
    return p

def guess_severity(risk):
    r = risk.lower()
    if any(w in r for w in ["critical","eternalblue","bluekeep","rce","no auth","cleartext — critical","no authentication"]):
        return "CRITICAL"
    if any(w in r for w in ["cleartext","null session","anonymous","remote root","open relay","default password"]):
        return "HIGH"
    if any(w in r for w in ["weak","version","default","brute","enumeration","signing","possible"]):
        return "MEDIUM"
    return "LOW"


# ──────────────────────────────────────────────────────────────────────────────
# PHASE 1 — PORT & SERVICE SCANNING
# ──────────────────────────────────────────────────────────────────────────────

def phase_ports(target, out_dir, quick=False):
    section("PHASE 1 — PORT & SERVICE SCANNING")
    results = {"ports": [], "vuln_hints": [], "udp_ports": [], "os": ""}

    if not tool_exists("nmap"):
        error("nmap not found — brew install nmap")
        return results

    # masscan fast sweep → nmap service detection
    if tool_exists("masscan") and is_root():
        info(f"masscan — fast sweep on {target} ...")
        rate = "10000" if quick else "50000"
        out, _, _ = run_cmd(f"masscan {target} -p1-65535 --rate={rate} --open 2>/dev/null", timeout=120)
        open_ports = list(set(re.findall(r"port (\d+)/tcp", out or "")))
        if open_ports:
            success(f"masscan — open ports: {', '.join(sorted(open_ports, key=int))}")
            save(out_dir, "masscan.txt", out)
            port_list = ",".join(sorted(open_ports, key=int))
            info("Feeding to nmap for service detection ...")
            svc_out, _, _ = run_cmd(f"nmap -sV -sC -p {port_list} {target} 2>/dev/null", timeout=180)
            if svc_out:
                save(out_dir, "nmap_services.txt", svc_out)
                _parse_nmap(svc_out, results)
    elif not is_root():
        warn("masscan needs sudo — using nmap only")

    # Full nmap scan
    info(f"nmap — {'quick' if quick else 'full'} scan on {target} ...")
    flags = "-T4 --top-ports 1000 -sV -sC --open" if quick else "-T4 -p- -sV -sC --open"
    if not is_root():
        flags = flags.replace("-sS", "-sT")
    out, _, _ = run_cmd(f"nmap {flags} {target} 2>/dev/null", timeout=300)
    if out:
        save(out_dir, "nmap_full.txt", out)
        _parse_nmap(out, results)
        os_m = re.search(r"OS details?:\s*(.+)", out)
        if os_m:
            results["os"] = os_m.group(1).strip()
            success(f"OS detected: {results['os']}")

    # Deduplicate
    seen, unique = set(), []
    for p in results["ports"]:
        k = f"{p['port']}/{p['proto']}"
        if k not in seen:
            seen.add(k)
            unique.append(p)
    results["ports"] = sorted(unique, key=lambda x: int(x["port"]))

    if results["ports"]:
        if RICH:
            t = Table(title=f"Open Ports ({len(results['ports'])})", border_style="dim", show_lines=True)
            t.add_column("Port",    style="bold cyan", width=8)
            t.add_column("Proto",  width=6)
            t.add_column("Service",style="green")
            t.add_column("Version",style="dim")
            t.add_column("Risk Hints", style="yellow")
            for p in results["ports"]:
                svc = p["service"].lower()
                hints = []
                for key, risks in SERVICE_VULNS.items():
                    if key in svc:
                        hints = risks[:2]
                        break
                t.add_row(p["port"], p["proto"], p["service"],
                          p.get("version","")[:38], " | ".join(hints) if hints else "")
            console.print(t)
        else:
            for p in results["ports"]:
                print(f"  {p['port']}/{p['proto']:<4} {p['service']:<15} {p.get('version','')}")
        success(f"Found {len(results['ports'])} open ports")
    else:
        warn("No open ports found — try sudo for better results")

    # UDP scan
    if is_root() and tool_exists("nmap"):
        info("nmap — UDP scan on common risky ports ...")
        udp_out, _, _ = run_cmd(
            f"nmap -sU -p 53,67,68,69,111,123,137,161,500,514 --open {target} 2>/dev/null",
            timeout=90
        )
        if udp_out:
            udp_open = re.findall(r"(\d+)/udp\s+open", udp_out)
            if udp_open:
                results["udp_ports"] = udp_open
                save(out_dir, "nmap_udp.txt", udp_out)
                warn(f"Open UDP ports: {', '.join(udp_open)}")
            else:
                success("No risky UDP ports open")

    # Vuln hints
    for p in results["ports"]:
        svc = p["service"].lower()
        for key, risks in SERVICE_VULNS.items():
            if key in svc:
                for risk in risks:
                    results["vuln_hints"].append({
                        "port": p["port"], "service": p["service"],
                        "risk": risk, "severity": guess_severity(risk),
                    })

    if results["vuln_hints"]:
        sev_order = ["CRITICAL","HIGH","MEDIUM","LOW"]
        results["vuln_hints"].sort(key=lambda x: sev_order.index(x["severity"]) if x["severity"] in sev_order else 4)
        if RICH:
            t = Table(title="Service Risk Hints", border_style="dim")
            t.add_column("Port",     width=8)
            t.add_column("Service",  style="cyan")
            t.add_column("Risk",     style="yellow")
            t.add_column("Severity", width=10)
            colors = {"CRITICAL":"bold red","HIGH":"bright_red","MEDIUM":"yellow","LOW":"cyan"}
            for v in results["vuln_hints"]:
                c = colors.get(v["severity"],"white")
                t.add_row(v["port"], v["service"], v["risk"], f"[{c}]{v['severity']}[/{c}]")
            console.print(t)
        else:
            for v in results["vuln_hints"]:
                print(f"  [{v['severity']}] {v['port']}/{v['service']} — {v['risk']}")
        save(out_dir, "service_risks.json", results["vuln_hints"])

    return results


def _parse_nmap(output, results):
    for line in output.splitlines():
        m = re.match(r"\s*(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
        if m:
            results["ports"].append({
                "port": m.group(1), "proto": m.group(2),
                "service": m.group(3), "version": m.group(4).strip(),
            })


# ──────────────────────────────────────────────────────────────────────────────
# PHASE 2 — NETWORK SNIFFING
# ──────────────────────────────────────────────────────────────────────────────

def phase_sniff(target, out_dir, iface="en0", duration=30):
    section("PHASE 2 — NETWORK SNIFFING & TRAFFIC ANALYSIS")
    results = {"protocols": {}, "cleartext": [], "dns_queries": [], "suspicious": []}

    if not is_root():
        warn("Sniffing requires sudo — re-run: sudo python3 nethunt.py ...")
        return results

    if not tool_exists("tcpdump"):
        error("tcpdump not found — brew install tcpdump")
        return results

    pcap_file = out_dir / "capture.pcap"
    out_dir.mkdir(parents=True, exist_ok=True)

    target_filter = f"host {target}" if target and "/" not in target else ""
    info(f"Capturing on [bold]{iface}[/bold] for {duration}s ...")

    if RICH:
        with console.status(f"[bold cyan]Sniffing traffic for {duration}s ...", spinner="dots"):
            run_cmd(
                f"tcpdump -i {iface} {target_filter} -w {pcap_file} -G {duration} -W 1 2>/dev/null",
                timeout=duration + 10
            )
    else:
        print(f"Sniffing for {duration}s ...")
        run_cmd(
            f"tcpdump -i {iface} {target_filter} -w {pcap_file} -G {duration} -W 1 2>/dev/null",
            timeout=duration + 10
        )

    if not (pcap_file.exists() and pcap_file.stat().st_size > 0):
        warn("No traffic captured — check interface name with: ifconfig")
        return results

    success(f"Captured {pcap_file.stat().st_size} bytes — analyzing ...")

    # Protocol distribution
    proto_filters = {
        "HTTP":   "tcp port 80",
        "HTTPS":  "tcp port 443",
        "DNS":    "udp port 53",
        "FTP":    "tcp port 21",
        "Telnet": "tcp port 23",
        "SMTP":   "tcp port 25",
        "SMB":    "tcp port 445",
        "SSH":    "tcp port 22",
        "SNMP":   "udp port 161",
        "RDP":    "tcp port 3389",
    }
    cleartext_list = ["HTTP","FTP","Telnet","SMTP","SNMP"]

    for proto, flt in proto_filters.items():
        cnt, _, _ = run_cmd(f"tcpdump -r {pcap_file} {flt} 2>/dev/null | wc -l", timeout=10)
        count = int(cnt.strip()) if cnt.strip().isdigit() else 0
        if count > 0:
            results["protocols"][proto] = count
            if proto in cleartext_list:
                results["cleartext"].append(proto)

    # DNS queries
    dns_out, _, _ = run_cmd(
        f"tcpdump -r {pcap_file} -nn 'udp port 53' 2>/dev/null | grep -oE 'A\\? [^ ]+' | sort | uniq -c | sort -rn | head -15",
        timeout=10
    )
    if dns_out:
        results["dns_queries"] = dns_out.splitlines()

    # Large packet check (possible exfil)
    big, _, _ = run_cmd(f"tcpdump -r {pcap_file} -nn 2>/dev/null | awk 'length > 1400' | wc -l", timeout=10)
    big_n = int(big.strip()) if big.strip().isdigit() else 0
    if big_n > 100:
        results["suspicious"].append(f"Large packets (>1400 bytes): {big_n} — possible data exfiltration")

    # Print results
    if results["protocols"]:
        if RICH:
            t = Table(title="Protocol Distribution", border_style="dim")
            t.add_column("Protocol", style="cyan")
            t.add_column("Packets",  justify="right")
            t.add_column("Risk")
            for proto, count in sorted(results["protocols"].items(), key=lambda x: x[1], reverse=True):
                risk_str = "[red]⚠ CLEARTEXT[/red]" if proto in cleartext_list else "[dim]OK[/dim]"
                t.add_row(proto, str(count), risk_str)
            console.print(t)
        else:
            for proto, count in results["protocols"].items():
                flag = " ← CLEARTEXT!" if proto in cleartext_list else ""
                print(f"  {proto:<10} {count} packets{flag}")

    if results["cleartext"]:
        warn(f"Cleartext protocols active: {', '.join(results['cleartext'])}")

    if results["dns_queries"]:
        if RICH:
            console.print(Panel("\n".join(results["dns_queries"][:12]),
                                title="[cyan]DNS Queries", border_style="dim"))
        else:
            print("\n  DNS Queries:")
            for q in results["dns_queries"][:10]:
                print(f"    {q}")

    for s in results["suspicious"]:
        warn(f"Suspicious: {s}")

    save(out_dir, "traffic_analysis.json", results)
    return results


# ──────────────────────────────────────────────────────────────────────────────
# PHASE 3 — FIREWALL & ACL TESTING
# ──────────────────────────────────────────────────────────────────────────────

def phase_firewall(target, out_dir, quick=False):
    section("PHASE 3 — FIREWALL & ACL TESTING")
    results = {"acl_gaps": [], "evasion": [], "traceroute": "", "banners": {}}

    # Traceroute
    info(f"Traceroute to {target} ...")
    tr_out, _, _ = run_cmd(f"traceroute -n -m 20 {target} 2>/dev/null", timeout=30)
    if tr_out:
        results["traceroute"] = tr_out
        hops = [l for l in tr_out.splitlines() if re.match(r"\s*\d+", l)]
        save(out_dir, "traceroute.txt", tr_out)
        success(f"Traceroute: {len(hops)} hops")
        if RICH:
            console.print(Panel(tr_out[:600], title="[cyan]Traceroute", border_style="dim"))
    else:
        warn("Traceroute failed or target unreachable")

    # Evasion techniques
    info("Testing firewall evasion techniques ...")
    techniques = EVASION_TECHNIQUES[:3] if quick else EVASION_TECHNIQUES

    if RICH:
        t = Table(title="Firewall Evasion Tests", border_style="dim", show_lines=True)
        t.add_column("Technique",    style="cyan")
        t.add_column("nmap Flag",    style="dim", width=18)
        t.add_column("Open Ports",   justify="center", width=12)
        t.add_column("Result")

    evasion_rows = []
    for name, flag in techniques:
        needs_root = any(f in flag for f in ["-sS","-sN","-sF","-sX","-sA","-f"])
        if needs_root and not is_root():
            row = (name, flag, "—", "[dim]Skipped (needs sudo)[/dim]", [])
        else:
            cmd = f"nmap {flag} -p 22,80,443,3306,3389,8080 --open {target} 2>/dev/null"
            out, _, rc = run_cmd(cmd, timeout=25)
            found = re.findall(r"(\d+)/(?:tcp|udp)\s+open", out or "")
            if found:
                results["evasion"].append({"technique": name, "flag": flag, "ports": found})
                row = (name, flag, str(len(found)), f"[green]Bypassed — ports: {', '.join(found)}[/green]", found)
            else:
                row = (name, flag, "0", "[dim]Filtered / blocked[/dim]", [])
        evasion_rows.append(row)

    if RICH:
        for name, flag, ports, result, _ in evasion_rows:
            t.add_row(name, flag, ports, result)
        console.print(t)
    else:
        for name, flag, ports, _, found in evasion_rows:
            print(f"  {name:<25} ports open: {found if found else 'none'}")

    # ACL gap detection
    info("Probing for firewall ACL gaps on risky ports ...")
    port_list = ",".join(RISKY_PORTS.keys())
    out, _, _ = run_cmd(f"nmap -sT -p {port_list} --open {target} 2>/dev/null", timeout=60)

    acl_gaps = []
    for port, (service, severity) in RISKY_PORTS.items():
        if re.search(rf"{port}/tcp\s+open", out or ""):
            acl_gaps.append({"port": port, "service": service, "severity": severity})

    results["acl_gaps"] = acl_gaps

    if acl_gaps:
        if RICH:
            t = Table(title="⚠ Firewall ACL Gaps Detected", border_style="dim")
            t.add_column("Port",     style="bold", width=8)
            t.add_column("Service",  style="cyan")
            t.add_column("Severity", width=10)
            t.add_column("Action")
            colors = {"CRITICAL":"bold red","HIGH":"bright_red"}
            for g in acl_gaps:
                c = colors.get(g["severity"], "yellow")
                t.add_row(g["port"], g["service"],
                          f"[{c}]{g['severity']}[/{c}]",
                          f"Block port {g['port']}/tcp at perimeter")
            console.print(t)
        else:
            for g in acl_gaps:
                print(f"  [{g['severity']}] {g['service']} port {g['port']} exposed!")
        warn(f"{len(acl_gaps)} ACL gaps found — these ports should be firewalled")
    else:
        success("No ACL gaps found on risky ports")

    # Banner grabbing with netcat
    nc = "nc" if tool_exists("nc") else ("netcat" if tool_exists("netcat") else None)
    if nc:
        info("Banner grabbing with netcat ...")
        banners = {}
        for port in [21, 22, 25, 80, 8080]:
            out, _, rc = run_cmd(
                f"echo '' | {nc} -w 2 {target} {port} 2>/dev/null | head -3",
                timeout=5
            )
            if out and rc == 0:
                banners[str(port)] = out.strip()
                info(f"  Port {port}: {out[:80]}")
        if banners:
            results["banners"] = banners
            save(out_dir, "banners.txt", "\n".join(f":{p} → {b}" for p, b in banners.items()))
            success(f"Grabbed {len(banners)} service banners")

    save(out_dir, "firewall_results.json", results)
    return results


# ──────────────────────────────────────────────────────────────────────────────
# REPORT
# ──────────────────────────────────────────────────────────────────────────────

def phase_report(target, out_dir, all_results):
    section("REPORT — NETWORK VAPT SUMMARY")

    ports_r = all_results.get("ports",    {})
    sniff_r = all_results.get("sniff",    {})
    fw_r    = all_results.get("firewall", {})
    now     = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    open_ports  = ports_r.get("ports",      [])
    vuln_hints  = ports_r.get("vuln_hints", [])
    acl_gaps    = fw_r.get("acl_gaps",      [])
    cleartext   = sniff_r.get("cleartext",  [])
    evasion     = fw_r.get("evasion",       [])
    suspicious  = sniff_r.get("suspicious", [])

    critical = sum(1 for v in vuln_hints if v["severity"] == "CRITICAL") + \
               sum(1 for g in acl_gaps   if g["severity"] == "CRITICAL")
    high     = sum(1 for v in vuln_hints if v["severity"] == "HIGH") + len(cleartext)

    if   critical > 0: overall, rc = "CRITICAL", "bold red"
    elif high > 2:     overall, rc = "HIGH",     "bright_red"
    elif high > 0:     overall, rc = "MEDIUM",   "yellow"
    else:              overall, rc = "CLEAN",    "green"

    if RICH:
        console.print(Panel(
            f"[bold]Target:[/bold]       {target}\n"
            f"[bold]Date:[/bold]         {now}\n"
            f"[bold]Overall Risk:[/bold] [{rc}]{overall}[/{rc}]\n\n"
            f"[bold]Open Ports:[/bold]   {len(open_ports)}\n"
            f"[bold]Vuln Hints:[/bold]   {len(vuln_hints)}  (Crit:{critical} High:{high})\n"
            f"[bold]ACL Gaps:[/bold]     {len(acl_gaps)}\n"
            f"[bold]Cleartext:[/bold]    {', '.join(cleartext) or 'None'}\n"
            f"[bold]FW Evasion:[/bold]   {len(evasion)} techniques bypassed\n"
            f"[bold]Suspicious:[/bold]   {len(suspicious)}",
            title="[bold white]📋 NETHUNT REPORT",
            border_style="red" if overall in ["CRITICAL","HIGH"] else "green"
        ))
    else:
        print(f"\n  Target: {target} | Risk: {overall} | Ports: {len(open_ports)} | ACL Gaps: {len(acl_gaps)}\n")

    # Markdown
    lines = [
        f"# NetHunt Network VAPT Report",
        f"\n**Target:** `{target}`  \n**Date:** {now}  \n**Risk:** {overall}\n",
        "---\n",
        "## 1. Open Ports & Services\n",
    ]
    if open_ports:
        lines += ["| Port | Proto | Service | Version |","|---|---|---|---|"]
        for p in open_ports:
            lines.append(f"| {p['port']} | {p['proto']} | {p['service']} | {p.get('version','')[:40]} |")
    else:
        lines.append("No open ports found.\n")

    if vuln_hints:
        lines += ["\n### Service Risk Hints\n","| Port | Service | Risk | Severity |","|---|---|---|---|"]
        for v in vuln_hints:
            lines.append(f"| {v['port']} | {v['service']} | {v['risk']} | **{v['severity']}** |")

    lines += ["\n---\n","## 2. Traffic Analysis\n"]
    proto_data = sniff_r.get("protocols", {})
    if proto_data:
        lines += ["| Protocol | Packets |","|---|---|"]
        for proto, count in proto_data.items():
            lines.append(f"| {proto} | {count} |")
    if cleartext:
        lines.append(f"\n⚠ **Cleartext protocols:** {', '.join(cleartext)}")
    for s in suspicious:
        lines.append(f"\n⚠ **Suspicious:** {s}")

    lines += ["\n---\n","## 3. Firewall & ACL Testing\n"]
    if acl_gaps:
        lines += ["### ACL Gaps\n","| Port | Service | Severity |","|---|---|---|"]
        for g in acl_gaps:
            lines.append(f"| {g['port']} | {g['service']} | **{g['severity']}** |")
    else:
        lines.append("No ACL gaps found.\n")
    if evasion:
        lines.append("\n### Evasion Successes\n")
        for e in evasion:
            lines.append(f"- **{e['technique']}** bypassed — open: {', '.join(e['ports'])}")

    lines += ["\n---\n","## 4. Recommendations\n"]
    recs = []
    if critical > 0:    recs.append("🔴 Patch critical service vulnerabilities immediately")
    if cleartext:       recs.append(f"🔴 Disable cleartext protocols: {', '.join(cleartext)}")
    if acl_gaps:        recs.append(f"🟠 Firewall {len(acl_gaps)} exposed risky ports")
    if evasion:         recs.append("🟡 Harden firewall ruleset — evasion techniques succeeded")
    if ports_r.get("udp_ports"): recs.append(f"🟡 Review UDP ports: {', '.join(ports_r['udp_ports'])}")
    if not recs:        recs.append("✅ No critical issues. Maintain regular scanning schedule.")
    for r in recs:
        lines.append(f"- {r}")

    lines.append(f"\n---\n*Generated by NetHunt — {now}*")

    rp = save(out_dir, "NETWORK_VAPT_REPORT.md", "\n".join(lines))
    success(f"Report → {rp}")

    if RICH:
        console.print("\n[bold]Output files:[/bold]")
        for f in sorted(out_dir.glob("*")):
            console.print(f"  [dim]📄[/dim] {f.name}")
    else:
        print("\nOutput files:")
        for f in sorted(out_dir.glob("*")):
            print(f"  {f.name}")


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NetHunt — Automated Network VAPT CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  Full scan:
    sudo python3 nethunt.py -t 192.168.1.1 --all

  Port scan only:
    sudo python3 nethunt.py -t 192.168.1.1 --ports

  Sniff 60s on en0:
    sudo python3 nethunt.py --sniff --iface en0 --duration 60

  Firewall testing:
    sudo python3 nethunt.py -t 192.168.1.1 --firewall

  Quick mode:
    sudo python3 nethunt.py -t 192.168.1.1 --all --quick

  Check tools installed:
    python3 nethunt.py --check-tools

NOTE: Most features need sudo for raw packet access.
        """
    )
    parser.add_argument("-t","--target",     help="Target IP, hostname, or CIDR (e.g. 192.168.1.1)")
    parser.add_argument("--all",             action="store_true", help="Run all phases")
    parser.add_argument("--ports",           action="store_true", help="Port & service scan")
    parser.add_argument("--sniff",           action="store_true", help="Traffic sniffing & analysis")
    parser.add_argument("--firewall",        action="store_true", help="Firewall & ACL testing")
    parser.add_argument("--iface",           default="en0",       help="Interface for sniffing (default: en0)")
    parser.add_argument("--duration",        type=int, default=30,help="Sniff duration seconds (default: 30)")
    parser.add_argument("--quick",           action="store_true", help="Faster, fewer checks")
    parser.add_argument("--output",          help="Custom output directory")
    parser.add_argument("--check-tools",     action="store_true", help="Check installed tools")

    args = parser.parse_args()
    print_banner()

    if args.check_tools:
        section("Tool Check")
        for tool, install in [("nmap","nmap"),("masscan","masscan"),("tcpdump","tcpdump"),("nc","netcat")]:
            if tool_exists(tool):
                success(f"{tool} — found")
            else:
                warn(f"{tool} — NOT found  →  brew install {install}")
        sys.exit(0)

    if not args.target and not args.sniff:
        parser.print_help()
        sys.exit(0)

    target  = (args.target or "").replace("https://","").replace("http://","").rstrip("/")
    out_dir = Path(args.output) if args.output else OUTPUT_DIR / target.replace("/","_")
    out_dir.mkdir(parents=True, exist_ok=True)

    if RICH:
        console.print(f"[bold]Target:[/bold]  [green]{target or '(interface only)'}[/green]")
        console.print(f"[bold]Output:[/bold]  [dim]{out_dir}[/dim]")
        console.print(f"[bold]Sudo:  [/bold]  {'[green]Yes ✔[/green]' if is_root() else '[yellow]No — some tests will be skipped[/yellow]'}\n")
        console.print(Panel(
            "[yellow]Only test networks you own or have written authorization to test.\nUnauthorized scanning is illegal.[/yellow]",
            title="⚠  Legal Disclaimer", border_style="yellow"
        ))
    else:
        print(f"Target : {target}\nSudo   : {is_root()}\n")
        print("⚠  Only scan networks you are authorized to test.\n")

    all_results = {}
    try:
        if args.ports    or args.all: all_results["ports"]    = phase_ports(target, out_dir, args.quick)
        if args.sniff    or args.all: all_results["sniff"]    = phase_sniff(target, out_dir, args.iface, args.duration)
        if args.firewall or args.all: all_results["firewall"] = phase_firewall(target, out_dir, args.quick)

        if any([args.ports, args.sniff, args.firewall, args.all]):
            phase_report(target, out_dir, all_results)

        section("COMPLETE")
        success(f"All results saved to: {out_dir}/")

    except KeyboardInterrupt:
        warn("\nScan interrupted.")
        sys.exit(0)

if __name__ == "__main__":
    main()

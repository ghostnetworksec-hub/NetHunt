# NetHunt 🌐
### Automated Network VAPT CLI — No AI, No API Keys

---

## ⚡ Setup

```bash
# Optional — nicer terminal output
pip3 install rich

# Make executable
chmod +x nethunt.py

# Verify your tools
python3 nethunt.py --check-tools
```

---

## 🔧 Required Tools

```bash
brew install nmap masscan
# tcpdump and nc are pre-installed on macOS
```

---

## 🚀 Commands

```bash
# Full scan — single host
sudo python3 nethunt.py -t 192.168.1.1 --all

# Full scan — entire subnet
sudo python3 nethunt.py -t 192.168.1.0/24 --all

# Port & service scan only
sudo python3 nethunt.py -t 192.168.1.1 --ports

# Firewall & ACL testing only
sudo python3 nethunt.py -t 192.168.1.1 --firewall

# Sniff traffic (30 seconds, auto-detect interface)
sudo python3 nethunt.py --sniff

# Sniff specific interface for 60 seconds
sudo python3 nethunt.py --sniff --iface en0 --duration 60

# Sniff and filter by target IP
sudo python3 nethunt.py --sniff --iface en0 --duration 30 -t 192.168.1.1

# Quick mode (faster, top 1000 ports)
sudo python3 nethunt.py -t 192.168.1.1 --all --quick

# Custom output directory
sudo python3 nethunt.py -t 192.168.1.1 --all --output ./results
```

> Most features need `sudo` for raw socket access.

---

## 📁 Output Files

```
nethunt_output/192.168.1.1/
├── nmap_full.txt               ← Full nmap scan with scripts
├── masscan.txt                 ← Fast masscan sweep
├── banners.txt                 ← Service banners (nc)
├── firewall_ack_scan.txt       ← Firewall ACK scan results
├── evasion_results.json        ← Firewall bypass test results
├── acl_issues.json             ← Exposed management ports
├── traceroute.txt              ← Network path analysis
├── capture.pcap                ← Raw packet capture
├── traffic_dump.txt            ← Human-readable traffic
├── sniff_analysis.json         ← Protocol & IOC analysis
└── NETWORK_VAPT_REPORT.md      ← Full report
```

---

## What Each Phase Does

| Phase | Tools | What It Finds |
|---|---|---|
| `--ports` | nmap, masscan, nc | Live hosts, open ports, services, banners, OS detection |
| `--firewall` | nmap | Firewall presence, evasion bypasses, ACL misconfigs, traceroute |
| `--sniff` | tcpdump | Protocols, cleartext creds, DNS queries, suspicious traffic |

---

## ⚠️ Legal Notice

Only use on networks you **own** or have **written authorization** to test.
Unauthorized network scanning and sniffing is illegal.

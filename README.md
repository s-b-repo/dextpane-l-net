# ActiveProxyAmpScanner

A next-generation toolkit for high-throughput proxy discovery, Layer 4/Layer 7 amplification scanning, and HTTP-based proxy attack orchestration — all wrapped in an intuitive web dashboard.

---

## 🚀 Features

- **Active Proxy Scanner**  
  - Asynchronously crawl public lists and random IP ranges to discover HTTP/SOCKS5 proxies  
  - Validate proxies for anonymity level, latency, and throughput  
  - Persist working proxies to a database (SQLite/PostgreSQL)

- **Layer 4 & Layer 7 Amplification Scanner**  
  - Built-in support for common L4 amplifiers (e.g. DNS, NTP, SNMP, Memcached)  
  - HTTP/HTTPS reflection checks for L7 amplification potential  
  - Automatic amplification factor calculation  
  - Safe “dry-run” discovery mode to audit susceptible hosts without traffic generation

- **Proxy-Based HTTP Flood Module (L7 Attacks)**  
  - Rotate through your validated proxy pool for stealthy HTTP(s) floods  
  - Customizable request templates (URL, headers, payloads)  
  - Concurrency controls 

- **Web Dashboard**  
  - Live charts: proxy pool health, scan progress, amplification candidates  
  - Schedule recurring scans or one-off campaigns  
  - Launch L4/L7 tests with preconfigured profiles  
  - Detailed logs & export (CSV/JSON)

---

## 📦 Installation

> Tested on Ubuntu 22.04 / Debian 12 / CentOS 8

1. **Clone the repo**  
   ```bash
   git clone https://github.com/your-org/ActiveProxyAmpScanner.git
   cd ActiveProxyAmpScanner

# Wi‑Fi AP Hunter 
A Windows PowerShell “walk‑to‑find” Wi‑Fi AP locator that forces fresh scans, groups radios by AP mask, and shows live signal graphs + trend HUD to help you physically locate access points faster.

> Built for field work: walk slowly, watch the trend, and follow the strongest BSSID (or grouped AP mask).
> This script legitimately saved me hours, I tried finding a couple old APs in drop cieling just using a netsh wlan command that showed signal strength, however netsh uses caches files and doesnt update enough so I could never find my AP.
> This script uses the WLAN API that Windows provides directly, and you will know you are right under your AP when Signal Strength hits 100%!

---

## Features

- **Forces fresh Wi‑Fi scans** using Windows WLAN API (`WlanScan`) — avoids stale `netsh` cache.
- **BSSID tracking** with per‑radio history + peak signal.
- **AP grouping (Collapsed mode)** by mask (first 4 octets) so radios from the same AP stay together.
- **Live 3‑panel graphs (Collapsed)**:
  - **Collapsed panel:** mask max history (single dot series)
  - **Top1:** strongest BSSID graph
  - **Top2:** second strongest BSSID graph
- **HUD / status** with trend arrows and “VERY HOT” indicator at 100%.
- **Field-friendly**: fast refresh, minimal flicker, console title set to `Wi‑Fi AP Hunter 📡`.

---

## Requirements

- **Windows 10/11**
- **PowerShell 7+** (Windows PowerShell)  
  > Works great in Windows Terminal too.
- A Wi‑Fi adapter that supports scanning

---

## Quick Start

1. Clone the repo:
   ```powershell
   git clone https://github.com/BrodyGitsIT/wifi-ap-hunter.git
   cd wifi-ap-hunter
   pwsh -executionpolicy bypass -file .\wifi-ap-hunter.ps1
   

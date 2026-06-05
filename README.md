# 🔍 Home Lab Network Traffic Analyser

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)]()

A powerful packet sniffer that captures, parses, logs, and visualises every packet on your network interface using raw sockets. Built from scratch to understand the OSI model from the inside out — just like Wireshark, but in your terminal.

## ✨ Features

- 📡 **Raw Socket Capture** - Captures EVERY Ethernet frame on your interface (requires root)
- 🔧 **Manual Header Parsing** - Parses Ethernet, IPv4, TCP, UDP, ICMP headers using `struct`
- 💾 **SQLite Storage** - Persistent packet logging with thread-safe database operations
- 🚨 **Alert Engine** - Detects suspicious ports and NULL TCP scans
- 📊 **Live Dashboard** - Real-time terminal UI with `rich` library
- 🧵 **Multi-threaded** - Dedicated sniffer thread keeps dashboard responsive
- 📝 **Alert Logging** - Suspicious packets logged to `logs/alerts.log`

## 🏗️ Architecture
network-analyser/
├── main.py # Entry point, CLI args, thread orchestration
├── sniffer.py # Raw socket + capture loop (background thread)
├── parser.py # Parse Ethernet → IP → TCP/UDP/ICMP
├── db.py # SQLite operations + thread-safe connections
├── alerts.py # Suspicious port detection + NULL scan
├── dashboard.py # Rich Live terminal dashboard
├── data/
│ └── traffic.db # Auto-created SQLite database
├── logs/
│ └── alerts.log # Suspicious packet logs
└── requirements.txt # Dependencies

## 📋 Prerequisites

- **Operating System**: Linux (raw sockets require AF_PACKET)
- **Python**: 3.10 or higher
- **Root Access**: Required for raw socket operations
- **Network Interface**: Ethernet (eth0, ens33, etc.) or wireless

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/network-analyser.git
cd network-analyser

python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

pip install -r requirements.txt

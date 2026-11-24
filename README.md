# 🦉 OIKEScan

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Network%20/%20DNS-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-GPL--3.0-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OIKEScan** — IKE/IPsec VPN scanner & analyzer (aggressive mode, weak transforms, PSK risk) ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OIKEScan is an offline-first OwlSec tool for IKE/IPsec VPN scanner & analyzer (aggressive mode, weak transforms, PSK risk). It provides an interactive cyan terminal UI and a full CLI with multi-format export (TXT, Markdown, JSON, CSV, SARIF), designed for authorized security work on Linux.

---

## ✨ Features

- Scan and analyze IKE/IPsec VPN endpoints and transforms
- Highlight aggressive mode and weak cryptographic proposals
- Assess PSK exposure risk indicators
- Lab/authorized assessment workflow with clear reporting
- Interactive and CLI operation modes
- Export analysis artifacts for VPN hardening reviews

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OIKEScan OIKEScan.go
./OIKEScan --help
./OIKEScan --target 192.0.2.10
./OIKEScan --target vpn.example.com --format json
./OIKEScan --demo
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 275+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

**GNU General Public License v3.0** — © 2026 Owlsec LLC

This tool is free software: its full source code is published in this repository and you may study, modify and redistribute it under the GPL-3.0.

> Other OwlSec tools are separate, independent programs under their own terms; many remain proprietary.

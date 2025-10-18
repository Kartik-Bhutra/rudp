# Reliable UDP — QUIC-style Secure & Reliable Transport Over UDP

This repository contains a C implementation of a **reliable, secure UDP transport layer inspired by QUIC**.
It replaces the traditional **TCP + TLS 1.2 stack** with:
- user-space reliability (no retransmit delay due to HoL blocking)
- integrated TLS inside transport (using OpenSSL)
- low-latency connection setup

---

## ✨ Key Features

- **Built on raw UDP** — custom reliability logic (ACKs, retransmit, numbering)
- **Secure channel using TLS 1.2** (OpenSSL)
- **All application data fully encrypted**
- **Head-of-Line Blocking eliminated** through frame-level delivery
- **Multiple Connection IDs** — supports connection migration/NAT rebinding
- **2-RTT handshake** for first-time client connection
- **1-RTT handshake** for resumed connections
- **Cross-platform C implementation**
  - ✅ Windows (Winsock)
  - ✅ Linux / Unix (POSIX sockets)
- **Drop-in alternative to TCP + TLS 1.2**

---

## 🧱 Tech Stack

| Component | Technology |
|----------|------------|
| Language | C |
| Crypto | TLS 1.2 via OpenSSL |
| Transport | UDP Sockets |
| Platforms | Windows & Linux/Unix |

---

## 🧠 Core Concepts Implemented

### ✅ Reliable Transport on UDP
- Packet numbers
- Acknowledgements
- Retransmission logic
- Loss handling

### ✅ QUIC-style Connection Management
- Multiple connection IDs
- Stateless retry model
- 2-RTT initial handshake
- 1-RTT resumed session

### ✅ Security Integration
- TLS 1.2 handshake integrated at transport layer
- All frames encrypted end-to-end

### ✅ No Head of Line Blocking
Unlike TCP, packets are processed independently,
so a lost packet does **not stall all streams**.

---

## 🗂 Repository Structure


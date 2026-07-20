# 🛡️ Adaptive Privacy Observatory

A production-grade, dual-layer anti-fingerprinting system that intercepts high-entropy browser APIs and applies **deterministic, domain-isolated perturbations** to prevent cross-site tracking — without breaking websites.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-green.svg)](https://python.org)
[![Manifest V3](https://img.shields.io/badge/Chrome-Manifest%20V3-orange.svg)](https://developer.chrome.com/docs/extensions/mv3/)

---

## ✨ Features

| Layer | Feature | Description |
|-------|---------|-------------|
| 🔒 **Extension** | Canvas fingerprint protection | LSB perturbation on `getImageData`, `toDataURL`, `toBlob` |
| 🔒 **Extension** | Audio fingerprint protection | Sub-audible noise on `getFloatFrequencyData`, `getChannelData` |
| 🔒 **Extension** | WebGL identity spoofing | Deterministic GPU renderer/vendor rotation |
| 🔒 **Extension** | ClientRects defence | Micro-perturbation on `getBoundingClientRect`, `getClientRects` |
| 🔒 **Extension** | Navigator spoofing | `hardwareConcurrency`, `deviceMemory` normalization |
| 🧠 **Backend** | Heuristic classifier | Sub-ms rule-based fingerprinting detection |
| 📊 **Backend** | Entropy engine | Shannon entropy analysis per API |
| 🗄️ **Backend** | Policy cache | Async LRU cache with TTL and statistics |
| 📡 **Dashboard** | Real-time telemetry | Live event feed, activity charts, donut chart |
| 📡 **Dashboard** | Entropy visualization | Before/after entropy bars per API |

## 🏗️ Architecture

```
Chrome Extension (MAIN world)             Local Python Backend
┌────────────────────────────────┐        ┌─────────────────────────────────┐
│ API Hooks (Canvas/Audio/WebGL/ │◄──WS──►│ FastAPI + Heuristic Classifier  │
│ ClientRects/Navigator)         │        │ + Entropy Engine + Policy Cache  │
│ + Xoshiro128** PRNG Engine     │        └────────────────┬────────────────┘
└────────────────────────────────┘                         │
                                              ┌────────────▼────────────┐
                                              │  Real-Time Dashboard    │
                                              │  (Vanilla JS + CSS)     │
                                              └─────────────────────────┘
```

### How It Works

1. **Interception** — The extension overrides native browser API prototypes in the MAIN world before any page script runs
2. **Seeding** — Each domain gets a unique PRNG seed: `SplitMix32(Hash(origin + "|" + daily_salt))` → Xoshiro128\*\*
3. **Perturbation** — API return values receive deterministic LSB noise, imperceptible to humans but unique per domain
4. **Classification** — The backend classifies each API call's intent (fingerprint / legitimate / unknown) and adjusts noise
5. **Result** — `tracker.com` sees a stable fingerprint, but it's completely different from what `ad-network.com` sees

## 🚀 Quick Start

### Extension

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `extension/` directory
4. The shield icon appears — click it for the popup dashboard

### Backend

```bash
cd backend
python -m pip install -r requirements.txt
python main.py
```

Open `http://localhost:8000/dashboard` for the real-time dashboard.

### Docker

```bash
docker compose up -d
```

## 📁 Project Structure

```
adaptive-privacy-observatory/
├── extension/                  # Chrome extension (Manifest V3)
│   ├── manifest.json           # Extension config (popup, background, permissions)
│   ├── content.js              # API hooks + PRNG engine (MAIN world)
│   ├── injector.js             # Backend relay + script capture (ISOLATED world)
│   ├── background.js           # Service worker (badge, storage, alarms)
│   ├── popup.html/css/js       # Extension popup UI
│   ├── options.html/css/js     # Settings page
│   └── icons/                  # Extension icons (SVG)
├── backend/                    # Python FastAPI server
│   ├── main.py                 # Application entry point
│   ├── config.py               # Pydantic settings (env vars)
│   ├── models.py               # Request/response Pydantic models
│   ├── prng.py                 # Xoshiro128** (Python mirror)
│   ├── entropy_engine.py       # Shannon entropy calculator
│   ├── heuristic_classifier.py # Rule-based intent classifier
│   ├── policy_cache.py         # Async LRU cache with TTL
│   └── tests/                  # pytest suite (35+ tests)
├── dashboard/                  # Real-time web dashboard
│   ├── index.html              # Dashboard SPA
│   ├── styles.css              # Dark glassmorphism design
│   └── app.js                  # WebSocket client + charts
├── Dockerfile                  # Container build
├── docker-compose.yml          # One-command startup
├── LICENSE                     # MIT License
├── CONTRIBUTING.md             # Contributor guide
└── README.md                   # This file
```

## 🔌 API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ws/telemetry` | WebSocket | Extension telemetry events |
| `/ws/dashboard` | WebSocket | Real-time dashboard updates |
| `/api/health` | GET | Health probe (`{ status: "ok" }`) |
| `/api/status` | GET | Server status, uptime, stats |
| `/api/policies` | GET | Full policy cache dump |
| `/api/policies/{origin}` | DELETE | Invalidate a cached policy |
| `/api/entropy-summary` | GET | Entropy reduction per API |
| `/dashboard` | Static | Real-time dashboard UI |

## ⚙️ Configuration

All settings can be overridden via environment variables with the `APO_` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `APO_HOST` | `127.0.0.1` | Server bind address |
| `APO_PORT` | `8000` | Server port |
| `APO_LOG_LEVEL` | `info` | Log level (debug/info/warning/error) |
| `APO_CACHE_TTL_SECONDS` | `3600` | Policy cache TTL |
| `APO_CACHE_MAX_SIZE` | `10000` | Max cached policies (LRU) |
| `APO_CORS_ORIGINS` | localhost variants | Allowed CORS origins |

## 🧪 Testing

```bash
cd backend
python -m pytest tests/ -v --tb=short
```

The test suite covers:
- **PRNG** — Determinism, domain isolation, salt rotation, cross-language consistency
- **Entropy Engine** — Known API entropy, fallback estimation, reduction summaries
- **Heuristic Classifier** — Each rule individually, confidence aggregation, bounded history
- **Policy Cache** — TTL expiry, LRU eviction, access promotion, statistics
- **API Endpoints** — Health, status, policies, entropy summary, policy deletion

## 📜 License

[MIT](LICENSE) — see `LICENSE` for details.

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and PR process.

# Adaptive Privacy Observatory

A dual-layer anti-fingerprinting system that intercepts high-entropy browser APIs and applies deterministic, domain-isolated perturbations to prevent cross-site tracking.

## Architecture

```
Browser Extension (MAIN world)          Local Python Backend
┌──────────────────────────┐            ┌──────────────────────────┐
│ API Hooks (Canvas/Audio/ │◄──WS──────►│ FastAPI + ML Intent      │
│ WebGL) + PRNG Engine     │            │ Engine + Entropy Calc    │
└──────────────────────────┘            └──────────────────────────┘
                                                  │
                                         ┌────────▼────────┐
                                         │ Real-Time       │
                                         │ Dashboard (D3)  │
                                         └─────────────────┘
```

## Quick Start

### Extension
1. Open Chrome → `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked" → select the `extension/` directory
4. Visit any site — check the console for `[Observatory]` logs

### Backend (Phase 2+)
```bash
cd backend
pip install -r requirements.txt
python main.py
```

## Project Structure

```
adaptive-privacy-observatory/
├── extension/           # Chrome extension (Manifest V3, MAIN world)
│   ├── manifest.json    # Extension config
│   └── content.js       # API hooks + Xoshiro128** PRNG engine
├── backend/             # Python backend
│   ├── prng.py          # PRNG mirror (cross-language verification)
│   └── main.py          # FastAPI server (Phase 2)
├── dashboard/           # Real-time visualization (Phase 4)
└── verify_prng.js       # Cross-language PRNG consistency test
```

## How It Works

1. **Interception**: The extension overrides native browser API prototypes (`getImageData`, `toDataURL`, `getFloatFrequencyData`, WebGL `getParameter`) before any page script runs.

2. **Seeding**: Each domain gets a unique PRNG seed: `Hash(origin + daily_salt)`, expanded via SplitMix32 into 128 bits for Xoshiro128**.

3. **Perturbation**: API return values get deterministic LSB noise — imperceptible to humans but changes every fingerprint hash.

4. **Result**: `tracker.com` sees a stable fingerprint (avoiding bot detection), but it's completely different from the fingerprint `ad-network.com` sees, breaking cross-site correlation.

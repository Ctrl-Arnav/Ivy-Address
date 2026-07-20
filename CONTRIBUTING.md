# Contributing to Adaptive Privacy Observatory

Thank you for your interest in contributing! This guide will help you get set up.

## Development Setup

### Prerequisites

- **Python 3.12+** — backend server
- **Node.js 18+** — PRNG cross-language verification (optional)
- **Chrome/Chromium** — extension testing
- **Docker** — containerised deployment (optional)

### Backend

```bash
cd backend
python -m pip install -r requirements.txt
python main.py
```

The server starts at `http://127.0.0.1:8000`. Visit `/dashboard` for the UI.

### Extension

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `extension/` directory
4. The extension icon appears in the toolbar

### Running Tests

```bash
cd backend
python -m pytest tests/ -v
```

## Project Structure

```
├── backend/                 # Python FastAPI server
│   ├── main.py              # Application entry point
│   ├── config.py            # Pydantic settings
│   ├── models.py            # Request/response models
│   ├── prng.py              # Xoshiro128** PRNG (Python mirror)
│   ├── entropy_engine.py    # Shannon entropy calculator
│   ├── heuristic_classifier.py  # Rule-based intent classifier
│   ├── policy_cache.py      # Async LRU cache with TTL
│   └── tests/               # pytest suite
├── extension/               # Chrome extension (Manifest V3)
│   ├── manifest.json        # Extension configuration
│   ├── content.js           # API hooks (MAIN world)
│   ├── injector.js          # Backend relay (ISOLATED world)
│   ├── background.js        # Service worker
│   ├── popup.*              # Extension popup UI
│   └── options.*            # Settings page
├── dashboard/               # Real-time web dashboard
├── Dockerfile               # Container build
└── docker-compose.yml       # One-command startup
```

## Coding Standards

### Python
- Follow PEP 8 and PEP 257
- Type hints on all function signatures
- Docstrings on all public functions and classes
- Use `ruff` for linting: `python -m ruff check .`

### JavaScript
- Use strict mode (`"use strict"`)
- Prefer `const` over `let`, never use `var`
- JSDoc comments on public functions
- IIFE wrappers to avoid global pollution

## Pull Request Process

1. Fork the repository and create a feature branch
2. Make your changes with clear, descriptive commits
3. Add tests for new functionality
4. Ensure all tests pass: `python -m pytest tests/ -v`
5. Update documentation if needed
6. Open a PR with a clear description of what and why

## Reporting Issues

When reporting bugs, please include:

- **OS and browser version**
- **Steps to reproduce**
- **Expected vs actual behaviour**
- **Console logs** (both extension and backend)

## Code of Conduct

Be respectful, constructive, and collaborative. We're all here to build better privacy tools.

# SpecterGraph Task Execution Checklist

## Phase 1: Core Graph Models & Storage
- [x] Implement graph primitives in `spectergraph.core.graph` (`Node`, `Edge`, `PropertyGraph`)
- [x] Implement asset models in `spectergraph.core.models` (`AssetType`, `RiskLevel`)

## Phase 2: DNS & Cloud Takeover Detection
- [x] Define provider fingerprints in `config/fingerprints.yaml`
- [x] Implement `TakeoverAnalyzer` in `spectergraph.engine.takeover`
- [x] Implement asynchronous DNS resolver in `spectergraph.engine.dns`

## Phase 3: Exposure Probing
- [x] Implement sensitive path probe in `spectergraph.engine.prober` (`.git`, `.env`, API docs)
- [x] Concurrent async HTTP dispatcher with rate limiting

## Phase 4: Visualization & Reporting
- [x] Implement standalone HTML graph visualizer in `spectergraph.export.html`
- [x] Implement JSON and Markdown report generators in `spectergraph.export.report`
- [x] CLI entry point in `spectergraph.cli`

## Phase 5: Testing, CI/CD & Delivery
- [x] Unit tests for Graph Engine (`tests/test_graph.py`)
- [x] Unit tests for Takeover Analyzer (`tests/test_takeover.py`)
- [x] Unit tests for Exposure Prober (`tests/test_prober.py`)
- [x] Integration scan test with mock DNS and HTTP targets (`tests/test_scan.py`)
- [x] Dockerfile & GitHub Actions workflow (`.github/workflows/ci.yml`)

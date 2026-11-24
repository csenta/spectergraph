# Contributing to SpecterGraph

Thank you for contributing to SpecterGraph!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/csenta/spectergraph.git
   cd spectergraph
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the test suite:
   ```bash
   python3 -m unittest discover -s tests -v
   ```

## Adding Cloud Takeover Fingerprints

To add new cloud provider fingerprints:
1. Edit `config/fingerprints.yaml`.
2. Provide regex for `cname_patterns` and `response_patterns`.
3. Add a unit test in `tests/test_takeover.py`.

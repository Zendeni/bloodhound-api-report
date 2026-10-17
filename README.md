# BloodHound CE API Report

A small Python CLI for repeatable Active Directory lab review with BloodHound
Community Edition. It validates collector ZIP files, optionally uploads them,
waits for BloodHound graph analysis, runs a focused Cypher assessment, and
exports results in formats that can be searched or included in a write-up.

## What it checks

- The selected principal and its transitive group memberships
- Direct outbound relationships and effective dangerous rights
- Effective administration and remote-access relationships to computers
- The shortest available path to Domain Admins
- AS-REP roastable and Kerberoastable users
- Weak account password-policy flags
- Unconstrained delegation
- Domain controllers present in the graph

## Output

Each run creates:

```text
report/
├── report.md
├── report.json
├── inventory.json              # when a collector ZIP is supplied
└── <query-name>/
    ├── query.cypher
    ├── raw.json
    ├── nodes.csv
    └── edges.csv
```

The Markdown report is intended for quick review. JSON and CSV files preserve
the underlying data for filtering, automation, and evidence collection.

## Requirements

- Python 3.10 or newer
- A reachable BloodHound CE instance for graph analysis
- A SharpHound or `bloodhound-python` collection ZIP when importing data

Clone and install into a virtual environment:

```bash
git clone git@github.com:Zendeni/bloodhound-api-report.git
cd bloodhound-api-report
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Authentication

Use a BloodHound API token:

```bash
export BH_TOKEN='<token>'
```

Or provide a username and let the tool request the password without echoing it:

```bash
export BH_USERNAME=admin
```

For non-interactive use, `BH_PASSWORD` is also supported. Keep tokens and
passwords out of shell history, reports, and version control.

## Usage

Import a collector ZIP and assess one user:

```bash
BH_USERNAME=admin python3 bh_report.py \
  --url http://127.0.0.1:8081 \
  --zip loot/bloodhound/collection.zip \
  --principal USER@LAB.LOCAL \
  --output loot/bloodhound/report
```

Query data that is already in BloodHound by omitting `--zip`:

```bash
BH_USERNAME=admin python3 bh_report.py \
  --url http://127.0.0.1:8081 \
  --principal USER@LAB.LOCAL \
  --output loot/bloodhound/report
```

To validate and inventory a collector ZIP without contacting BloodHound:

```bash
python3 bh_report.py \
  --offline \
  --zip loot/bloodhound/collection.zip \
  --output loot/bloodhound/offline-inventory
```

Run `python3 bh_report.py --help` for timeout, TLS, upload, and report-size
options.

### Principal and domain handling

`--principal` is required for online analysis. Use either `NAME@DOMAIN` or a
bare `NAME` together with `--domain DOMAIN`. If both arguments include a
domain, they must match.

### Reusing the tool across labs

BloodHound persists imported graph data. Use a clean BloodHound datastore for
each lab, or explicitly clear the previous lab before importing a new one.
Domain filtering limits these reports but cannot prevent contamination when
unrelated labs reuse the same domain or object names.

Offline mode only validates collection structure and object counts. Nested
membership, effective rights, and attack paths require BloodHound's analyzed
graph and are queried through `/api/v2/graphs/cypher`.

## Scope

This tool reports on data already collected from an Active Directory
environment. Use it only in environments you own or are explicitly authorized
to assess.

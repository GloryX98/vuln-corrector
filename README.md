# Vuln Rating & CVSS Corrector

Corrects the **Vulnerability Rating** and **CVSS** columns of a Nessus/Tenable
findings sheet by mapping each finding back to Tenable (with an NVD fallback) and
rewriting those two columns to the authoritative value. Everything else in the
sheet — all other columns, row order, the header — is left untouched, and the
input file itself is never modified (a `*_corrected` copy is written).

> Requires an internet connection: it queries `tenable.com` and, as a fallback,
> `services.nvd.nist.gov`.

**Cross-platform:** the script uses only the Python standard library for HTTP
(`urllib`), so it runs unchanged on **Windows, macOS and Linux** with a stock
Python 3. `openpyxl` is needed only for `.xlsx` input; plain CSV needs nothing extra.

## What it does to each row

1. Finds the finding's authoritative CVSS v3 base score by taking the **worst of**:
   - the highest-scoring CVE listed on the row (Tenable CVE page → NVD API), and
   - the Tenable plugin matched by the finding's exact title.
   (Nessus assigns a plugin the severity of its worst CVE, and rows sometimes
   under-list CVEs, so the plugin lookup is a safety net.)
2. Sets **Vulnerability Rating** = the risk factor (Low / Medium / High / Critical).
3. Sets **CVSS** = the base score rounded to a whole number, then clamped into the
   rating's band so score and rating always agree:

   | Rating   | CVSS band |
   |----------|-----------|
   | Low      | 2 – 3     |
   | Medium   | 4 – 6     |
   | High     | 7 – 8     |
   | Critical | 9 – 10    |

   (e.g. Tenable 6.5 Medium → 6, never 7; 8.8 High → 8; 9.8 Critical → 10.)

Rows whose finding cannot be resolved online are left exactly as they were.

## Usage

Windows (prebuilt `vuln_corrector.exe`):
```
vuln_corrector.exe  findings.csv
vuln_corrector.exe  findings.xlsx  -o fixed.xlsx  --report changes.csv
vuln_corrector.exe                         # no args → it asks for the path
```
You can also drag a `.csv`/`.xlsx` file onto `vuln_corrector.exe`.

macOS / Linux (binary built with `build.sh`, or straight from source):
```
./vuln_corrector  findings.csv
python3 vuln_corrector.py  findings.csv    # no build needed for CSV
```

### Options

| Option | Meaning |
|--------|---------|
| `-o, --output PATH` | Where to write the corrected sheet (default `<input>_corrected.<ext>`) |
| `--inplace` | Overwrite the input file instead of writing a copy |
| `--report PATH` | Also write a CSV log of every change (before → after) |
| `--title-col / --rating-col / --cvss-col / --cve-col` | Override auto-detected column names |

Columns are auto-detected (e.g. `Vulnerability_Title`, `Vulnerability_Rating`,
`CVSS`, `CVE`, plus common variants like `Severity`, `Risk_Factor`, `Base_Score`).
If detection misses, name them explicitly with the `--*-col` options.

## Running from source (any OS, no build)

```
# CSV needs nothing but Python 3. For XLSX support:
pip install -r requirements.txt
python3 vuln_corrector.py findings.csv        # use 'python' on Windows
```

## Prebuilt binaries (all three OSes)

Native, standalone executables are built automatically by GitHub Actions and
published on the **[Releases](../../releases)** page:

| OS | File | How to run |
|----|------|-----------|
| Windows | `vuln_corrector-windows-x64.exe` | double-click, or `vuln_corrector-windows-x64.exe findings.csv` |
| macOS   | `vuln_corrector-macos-arm64`      | `chmod +x vuln_corrector-macos-arm64 && ./vuln_corrector-macos-arm64 findings.csv` |
| Linux   | `vuln_corrector-linux-x64`        | `chmod +x vuln_corrector-linux-x64 && ./vuln_corrector-linux-x64 findings.csv` |

> macOS/Linux executables have **no file extension** — that is the normal
> convention on those systems; mark them executable with `chmod +x` and run.

Every push to `main` also uploads the three binaries as downloadable **workflow
artifacts** under the Actions tab; pushing a version tag (e.g. `git tag v1.0.0 &&
git push origin v1.0.0`) cuts a Release with all three attached.

## Building a standalone binary yourself (per OS)

PyInstaller cannot cross-compile, so build on the OS you want a binary for:

| OS | Command | Output |
|----|---------|--------|
| Windows | `build.bat`  (or `python build.py`)  | `dist\vuln_corrector.exe` |
| macOS   | `./build.sh` (or `python3 build.py`) | `dist/vuln_corrector` |
| Linux   | `./build.sh` (or `python3 build.py`) | `dist/vuln_corrector` |

On macOS/Linux make the scripts executable first: `chmod +x build.sh`.

### macOS notes
- If HTTPS lookups fail with a certificate error on a python.org build, run once:
  `/Applications/Python\ 3.x/Install\ Certificates.command`.
- The unsigned binary may be blocked by Gatekeeper on first run — allow it under
  *System Settings → Privacy & Security*, or run the script from source instead.

## Notes & limits

- CVSS base scores are computed **deterministically from the CVSS v3 vector**
  (official 3.1 formula), not screen-scraped numbers, so they are reproducible.
- The Tenable plugin-name search is best-effort; a finding with an unusual title
  and no CVE may come back "not found" and is then left unchanged — check those
  by hand.
- NVD's public API is rate-limited without a key; large sheets run with small
  pauses and automatic backoff, so a big file may take a few minutes.

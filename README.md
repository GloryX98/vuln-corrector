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

The executable has **two modes**:

- **Double-click it (no arguments)** → it starts a local web interface and opens
  your browser. It listens only on your machine (an uncommon local port, default
  `43117`) — nothing is exposed to the internet. The page talks only to the local
  app; the app is what queries Tenable in the background.
- **Give it a file (or `--cli`)** → classic command-line correction.

```
vuln_corrector.exe                         # web interface (double-click)
vuln_corrector.exe  findings.csv           # command line
vuln_corrector.exe  findings.xlsx  -o fixed.xlsx  --report changes.csv
vuln_corrector.exe  --web                  # force the web interface
```
You can also drag a `.csv`/`.xlsx` file onto `vuln_corrector.exe` to run the CLI.

macOS / Linux (binary built with `build.sh`, or straight from source):
```
./vuln_corrector                 # web interface
./vuln_corrector  findings.csv   # command line
python3 launch.py                # from source: web interface
python3 vuln_corrector.py findings.csv   # from source: CLI
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

## Browser UI (no command line)

Just double-click the executable — it launches the web interface and opens your
browser at `http://127.0.0.1:43117`. Drag the sheet in, watch progress, download
the corrected file.

- It listens **only on your machine** (localhost), never on the network.
- The **browser never contacts Tenable** — it only talks to the local app, which
  performs the Tenable/NVD lookups itself and returns the results. (This is also
  why it can't be a pure static page: cross-site calls to Tenable are blocked by
  CORS.)
- Nothing is stored on the server once you download the result.

From source instead of the exe:
```
python launch.py             # or: python webui.py
# or: web/run_web.bat  (Windows)   |   ./web/run_web.sh  (macOS/Linux)
```

The port `43117` is uncommon and below the range Windows reserves; if it is ever
busy the app moves to the next free port and prints the exact URL. Only the
standard library is needed for CSV; `.xlsx` uploads need `openpyxl`.

### Host it online (optional)
A `Dockerfile` is included so it can be deployed anywhere that runs containers:

```
docker build -t vuln-corrector-web -f web/Dockerfile .
docker run --rm -p 8000:8000 vuln-corrector-web
```

It honours the `PORT`/`HOST` env vars, so it drops straight onto Render, Railway,
Fly.io, etc. Note: a public instance queries Tenable/NVD on every request, so keep
it private or add access control to avoid rate-limiting.

## Running from source (any OS, no build)

```
# CSV needs nothing but Python 3. For XLSX support:
pip install -r requirements.txt
python3 vuln_corrector.py findings.csv        # use 'python' on Windows
```

## Prebuilt binaries (all three OSes)

Native, standalone executables are built automatically by GitHub Actions and
published on the **[Releases](../../releases)** page:

| OS | File | Double-click → web UI / with a file → CLI |
|----|------|-----------|
| Windows | `vuln_corrector-windows-x64.exe` | double-click for the web UI, or `vuln_corrector-windows-x64.exe findings.csv` |
| macOS   | `vuln_corrector-macos-arm64`      | `chmod +x vuln_corrector-macos-arm64 && ./vuln_corrector-macos-arm64` |
| Linux   | `vuln_corrector-linux-x64`        | `chmod +x vuln_corrector-linux-x64 && ./vuln_corrector-linux-x64` |

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

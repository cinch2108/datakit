# Sheetwise security model

Sheetwise is a static site. Every spreadsheet operation runs **in the visitor's browser**. There is no backend, no upload endpoint, no database and no accounts.

## Threat model in one paragraph
The things worth protecting are the user's data and the integrity of the page. Data never leaves the device. Parsing and writing (SheetJS, Papa Parse, js-yaml) run in a Web Worker in the same tab. The CSP's `connect-src 'self' blob: data:` means page scripts *cannot* send data to another origin, even if a bug or a malicious file tried to. Page integrity comes from self-hosting every script, a strict CSP with no `unsafe-inline` or `unsafe-eval` (not even `wasm-unsafe-eval`), no inline event handlers, and `textContent`-only rendering of cell values.

## Controls

| Control | Where | Notes |
|---|---|---|
| Content-Security-Policy | `<meta>` in every page + `_headers`, `netlify.toml`, `vercel.json` | `default-src 'self'; script-src 'self'; worker-src 'self' blob:; connect-src 'self' blob: data:; img-src 'self' blob: data:; media-src 'self' blob:; style-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; manifest-src 'self'; frame-src 'none'`. The header version adds `frame-ancestors 'none'; upgrade-insecure-requests`. These can't go in a meta tag. |
| No inline script/style | all pages | Theme bootstrap is `/js/theme.js`. Dynamic sizes (virtual grid rows, chart canvas) use CSSOM, which CSP allows. JSON-LD blocks are data, not executed. |
| No inline event handlers | all pages | Listeners are attached with `addEventListener`. Tests grep the built HTML for `on*=` attributes. |
| Self-hosted dependencies | `/vendor/` | SheetJS CE 0.20.3 (Apache-2.0), Papa Parse 5.7.0 (MIT), js-yaml 4 (MIT), JSZip 3.10.2 (MIT, loaded only to build ZIP downloads). Zero third-party requests. |
| Headers | `_headers`/`netlify.toml`/`vercel.json` | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, HSTS, COOP/CORP `same-origin`, a Permissions-Policy that disables camera, microphone, geolocation, payment, USB, sensors and topics. No COEP is needed (no SharedArrayBuffer). On GitHub Pages only the meta CSP and meta referrer apply, because Pages can't set headers. |
| Input validation | `js/ops.js → sniff()` | Files are identified by **magic bytes**: ZIP container (`PK\3\4`) → XLSX/ODS, OLE2 (`D0 CF 11 E0`) → XLS. Text formats must contain no NUL bytes in the first 8 KB. PDF, PNG, GIF, JPEG, EXE/ELF, RAR, 7z, GZIP and MP4/MOV are rejected by name with a clear message. Empty files are rejected. |
| Size limits | `js/ops.js → limits()` | Text files up to 512 MB and workbooks up to 150 MB (256 MB / 80 MB when `navigator.deviceMemory ≤ 4`), max 50 files per batch. Workbooks are parsed in a worker, so a huge or malicious file can be cancelled with `worker.terminate()`. |
| XML | `DOMParser` with `application/xml` | No external entities or DTD fetching are possible in browsers. Parser errors are reported, not rendered. |
| Formula injection | CSV/TSV output option | "Protect against formula injection" prefixes cells starting with `= + - @` (and tab/CR) with `'`, for files that will be opened in Excel. |
| DOM safety | `js/app.js → h()`, `js/grid.js` | Cell values, headers and file names are only set via `textContent`/attributes. `innerHTML` is used only for constant SVG icons from `tools-meta.js`. HTML-table output escapes `& < > " '`. |
| Output names | `ops.safeFile()` | Path parts, control characters, bidi overrides and reserved characters are stripped, and the length is capped. |
| Object URLs | `js/app.js` | Every `blob:` URL is tracked and revoked when it is no longer needed and on `pagehide`. |
| Storage | `localStorage` only | Theme, favorites, recent tools, recent settings per tool, bytes processed locally, ad-consent choice. **No file contents are stored and no cookies are set.** |
| Tracking | none | No analytics, no fingerprinting, no third-party requests while ads are disabled. |

## Turning on ads (AdSense)
1. Edit **`src/js/ads-config.js`**: set `enabled: true`, your `client` (`ca-pub-…`) and slot IDs, then rebuild.
2. Widen `CSP_META` in `dev/build.mjs` for the AdSense script, frame, image and connect hosts, plus `style-src 'unsafe-inline'`. That is the main weakening, and AdSense requires it.
3. Your data still never leaves the device, but `connect-src` then allows Google ad endpoints.

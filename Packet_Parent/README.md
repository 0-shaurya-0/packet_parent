# PacketParent

A working local parental internet-activity monitoring prototype: **PCAP → metadata → SQLite → family rules → dashboard**.

## Start on Windows

1. Install Python 3.11 or newer if needed, with Python on PATH.
2. Double-click **Start PacketParent.bat**. It installs FastAPI, Uvicorn, and psutil if needed.
3. Open **http://127.0.0.1:8765**.
4. Create your parent password, or sign in with your existing one.
5. Install Wireshark with TShark and Npcap for live monitoring. Choose **WiFi** (or your connected Ethernet adapter), then click **Start monitoring** in the dashboard.
6. Browse normally. Completed segments appear automatically, usually within 15 seconds. Click **Stop monitoring** to stop capture.

The default **This PC · live** view shows real local activity for today. **Imported captures** is a separate view for files you import yourself. There is no sample-data mode, preloaded activity, or preloaded family rules. Choose yesterday in the date filter to see earlier history. Opening the Wireshark GUI alone does not feed this dashboard.

The application binds only to this computer's loopback interface. Keep its terminal running. Press Ctrl+C in that terminal to stop it. If port 8765 is already in use, stop the other PacketParent server before launching this copy. Use one server and one capture helper at a time.

From a terminal in this folder:

```powershell
python -m pip install -r requirements.txt
python app.py
```

No frontend build, external fonts, cloud account, or third-party web service is required. The UI uses HTML/CSS/JavaScript; the backend uses FastAPI and Python's SQLite module. The built-in capture parser allows uploads to work without Wireshark installed.

## Included features

- Parent password setup, login, logout, and protected API routes.
- Real PCAP and PCAPNG import, with a 25 MB / 150,000-packet limit.
- Visible DNS query, HTTP Host, and TLS server-name extraction.
- DNS-to-IP inference, explicitly labeled as inference.
- SQLite storage, duplicate-file detection, and duplicate-observation detection.
- Device naming and family-member labels.
- A small local domain category list; unmatched domains remain Unknown.
- Restricted-domain and restricted-category rules, optionally limited to a time window.
- Permitted-hours rules, including overnight schedules.
- Daily estimated internet-time limits, evaluated independently per device.
- Grouped, explainable alerts with a reviewed state.
- Daily/device filters, hourly activity chart, category breakdown, activity history, and session details.
- Dashboard Start/Stop monitoring controls, sensor status, and automatic completed-file ingestion.
- Five-second dashboard refresh, including Devices when you are not editing a device form.
- Persistent local PC identity across IP changes; filtering by local network addresses/MACs.
- Separate live and imported views; multicast discovery traffic excluded.
- Configurable session threshold, fixed UTC offset, and background-domain exclusions.

## What internet-active time means

1. Extract timestamped TCP/UDP payload observations involving this PC and a public unicast address. Generic imports instead recognize private source/destination IPs.
2. Exclude DNS-only lookups, payload-free TCP packets, common infrastructure ports, and configured background domains.
3. Sort and deduplicate activity timestamps per device.
4. Group timestamps into sessions while adjacent observations are no more than the configured threshold apart (default: 120 seconds).
5. Measure each session from first observation to last observation. Do not append an idle timeout to the end. A single isolated observation has zero duration.
6. Clip sessions at day/hour boundaries and add their durations.

All apps on one device share a single timeline, preventing concurrent apps from double-counting device time. The all-device overview adds the separate devices' totals; it is **device time**, not a household wall-clock total. If one child uses two devices simultaneously, this prototype does not merge their usage by person.

Gaps inside a session count toward the estimate. Background downloads can inflate it; buffering and quiet reading can reduce it. This is an estimate of network activity, not screen time or confirmed human attention.

## Capture real traffic

For the first experiment, run Wireshark on the monitored test device, select its active network interface, browse a few websites, stop capture, and save as PCAP/PCAPNG. Import the saved file into PacketParent.

Capturing on another ordinary laptop merely connected to the same Wi-Fi usually will not reveal the monitored device's traffic. A gateway capture must observe the LAN side before NAT to retain individual private IP addresses.

### Continuous capture

Install Wireshark with TShark and Npcap. Start/stop capture from the dashboard, or use the terminal commands below. TShark is optional for file uploads and is not bundled with this project.

```powershell
python capture.py --list
python capture.py --interface 1
```

Replace `1` with the desired interface from the list. Keep the dashboard server running too. The helper captures ten-second segments, then moves completed files into `data/inbox`. The server watches that folder and automatically imports completed captures. Capture files remain there until you remove them. The helper uses a 2,048-byte snapshot limit, a local MAC capture filter, and non-promiscuous mode. Segments are bounded by duration, file size, and packet count. Large or split handshakes may still be truncated. Stopping discards the unfinished segment; completed history is retained.

The dashboard distinguishes the inbox watcher from a running capture sensor. Short capture gaps can occur while the helper restarts TShark between segments. The local Windows WiFi → TShark → inbox → SQLite → dashboard flow was verified with a real capture. The helper reads the running dashboard’s data directory, and refuses an explicitly conflicting PACKETPARENT_DATA setting. Each data directory permits one sensor process at a time.

## Data and architecture

```text
Uploaded PCAP/PCAPNG ─┐
Completed inbox file ─┘─> packets.py ─> service.py ─> SQLite
                                         │              │
                                  Categorize / rules     │
                                                        ▼
                                             app.py (FastAPI)
                                                        │
                                             static/ (dashboard)
```

| File | Responsibility |
|---|---|
| `app.py` | HTTP routes, parent sessions, upload handling, inbox watcher |
| `packets.py` | Capture-format parsing and observable network metadata |
| `service.py` | Database, category matching, internet sessions, rules, alerts |
| `capture.py`, `capture_agent.py` | TShark segment capture and process lifecycle |
| `local_monitor.py` | Shared data path, stable PC identity, adapter discovery, status |
| `repair_history.py` | Backed-up repair of matching legacy local captures |
| `static/` | Responsive dashboard and API client |
| `tests/test_packetparent.py` | Parser, estimator, persistence, and API tests |

SQLite tables: `config`, `devices`, `captures`, `events`, `rules`, and `alerts`. WAL mode is enabled, and application writes are serialized. Uploaded raw captures are parsed in memory; the application stores metadata rather than raw payloads. Files produced by the optional capture helper are retained in the inbox.

By default the database is `data/packetparent.sqlite3`. The `PACKETPARENT_DATA` environment variable can redirect runtime data, including the inbox, to a separate directory. Do not share runtime data or a configured database as part of the source package.

A fresh extracted source package has no configured password and asks you to create one. Existing passwords are preserved during an update. Keep `data/local-device.json` with your database: it holds this installation’s persistent device ID.

### Repair older local history

Stop monitoring and the server, then run `python repair_history.py` from the project folder. It reparses numeric helper-generated captures still present in `data/inbox`, matching this PC by its current adapter MAC addresses. It creates a SQLite backup in `data/backups`, preserves password/settings and custom device labels, and removes orphan device records after removing discovery traffic. Captures that cannot be attributed to this PC are left as imports. This command is repeatable; already repaired captures are skipped. MAC randomization or replacing an adapter may prevent old history from matching.

## Prototype boundaries

- Monitoring and alerts only; there is no website blocking or device enforcement.
- No HTTPS decryption, full URL recovery from encrypted traffic, exact video identification, or browser extension.
- DNS visibility can be reduced by encrypted DNS, cached DNS, VPNs, and encrypted ClientHello. Unknown IP connections remain visible and can contribute to the time estimate.
- DNS-to-IP association can be ambiguous on shared infrastructure. The parser never labels it as confirmed page viewing.
- Live DNS/flow inference is carried across segments while the server runs, with expiration. Generic imports have independent inference state. Restarting the server clears this temporary cache.
- Supported link types: Ethernet (including VLAN), raw IPv4/IPv6, BSD loopback, Linux cooked v1/v2. PCAPNG supports enhanced packet blocks and per-interface timestamp resolution/offset. Export legacy or untimestamped blocks as classic PCAP.
- Generic imports recognize RFC1918 IPv4 and IPv6 ULA devices. Live capture matches this PC by local addresses or Ethernet MAC, including public IPv6. Captures on virtual/tunnel adapters may require selecting the correct physical adapter.
- No IP fragment or TCP stream reassembly. DNS over UDP, a complete visible TLS ClientHello within one packet, and HTTP Host within one packet are supported. Some captures therefore have less domain visibility.
- Live monitoring uses one persistent ID for this installation; imported gateway captures still use local IP identity. This is a single-PC sensor, not a router-wide discovery service.
- Domain categories are a small editable code list, not a comprehensive content classification service. Background exclusions are also heuristic.
- Day boundaries and rule schedules use a fixed UTC offset, initialized from the browser. Daylight saving adjustments are manual.
- Capture timestamps establish when activity was observed; the system does not claim complete monitoring coverage or infer that missing data means offline time.
- One local parent account; no cloud synchronization, multiple household accounts, or remote access configuration.
- There is no automatic metadata retention policy or password-recovery workflow in this prototype. Keep the source package separate from `data`.

## Tests

```powershell
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

The tests cover classic PCAP byte orders and timestamp precision, PCAPNG interfaces/timestamps, DNS name safety and expiry, TLS server-name extraction, malformed capture rejection, duplicate imports, domain boundaries, session overlap, zero-duration isolated traffic, midnight splits, background exclusions, rule changes, reviewed-alert persistence, authentication, and the API import/rule/device workflow.

For another local port:

```powershell
python -m uvicorn app:app --host 127.0.0.1 --port 8766
```

Live regression tests additionally cover multicast exclusion, IP changes, other-device rejection, cross-segment DNS expiry, source isolation, empty segments, backed-up history repair, and removal of legacy sample records.

## Existing sample records

On startup, older captures explicitly marked as synthetic demo data are removed from the active database after a SQLite backup is saved in `data/backups`. Their observations, alerts, and unused device entries are removed too. The original three untouched sample rules are removed when their complete original set is identifiable. Custom or edited rules are preserved. Real captures, passwords, settings, and device names you entered are preserved. A real device that shared a sample IP keeps its observations; its unchanged sample label is reset. Automated packet fixtures live only under `tests/` and cannot populate the dashboard.

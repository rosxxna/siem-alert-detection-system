# SIEM Alert Detection and Triage System

A Python-based SIEM simulator built to demonstrate core SOC analyst skills: log analysis, alert detection, alert prioritization, API-driven triage, and dashboard-based investigation.

This project was tested with real Windows Event Logs generated in a VM/Splunk lab. For privacy, the public repository uses a sanitized `sample_logs.json` file instead of raw lab logs. The sample file can be replaced with compatible exported logs from a lab environment.

## Project Overview

The system simulates a basic Security Information and Event Management workflow:

1. Load security logs from `sample_logs.json`.
2. Normalize logs into a common event schema.
3. Apply detection rules for suspicious activity.
4. Generate prioritized alerts.
5. Expose alerts through a Flask REST API.
6. Display alerts in a browser-based SOC dashboard.
7. Allow analysts to triage alerts as investigating, resolved, false positive, or escalated.

This is an educational and portfolio project, not a production SIEM replacement.

## Current Features

### Sample Log Ingestion

The project includes a sanitized dataset:

```text
sample_logs.json
```

Each event uses this normalized schema:

```json
{
  "timestamp": "2026-05-08T10:00:00+04:00",
  "source_ip": "192.168.1.105",
  "event_type": "Authentication",
  "action": "failed",
  "user": "admin",
  "details": "Windows Event ID 4625: An account failed to log on."
}
```

The project can also parse Splunk-style newline-delimited JSON exports when they are provided to the loader, but raw lab exports are not included in this repository because they may contain hostnames, usernames, SIDs, timestamps, and local file paths.

### Detection Engine

Implemented detections include:

| Rule | Severity | Detection Method |
| --- | --- | --- |
| Brute force | Medium | Multiple failed login events from the same source/user within a time window |
| SQL injection | High | Regex matching against request/log details |
| Privilege escalation | High | Suspicious privilege/admin-related commands or Windows event mappings |
| Malware indicators | Critical | Suspicious executable/script extensions in process or action fields |
| IP reputation | High/Medium | Match against a small local known-bad/suspicious IP list |

The engine also contains rule definitions that can be expanded, including data exfiltration and port scan detection.

### REST API

The Flask API provides alert retrieval, filtering, statistics, export, and triage actions.

### SOC Dashboard

`dashboard.html` provides a browser-based dashboard with:

- API health status
- Alert count and severity metrics
- Alert queue with severity/status/search filters
- Severity and threat breakdowns
- Alert triage form
- JSON and CSV export buttons

## Project Structure

```text
.
|-- README.md          # Project overview and setup guide
|-- siem_backend.py    # Detection engine, log loader, and normalization logic
|-- siem_api.py        # Flask REST API
|-- dashboard.html     # SOC dashboard UI
|-- sample_logs.json   # Sanitized sample dataset for GitHub
|-- requirements.txt   # Python dependencies
`-- .gitignore         # Local/private files excluded from Git
```

Private local files not included in GitHub:

```text
Windows_logs.json
PROJECT_GUIDE.md
PROJECT_STRATEGY.md
__pycache__/
```

## Quick Start

### 1. Install Requirements

```bash
pip install -r requirements.txt
```

### 2. Run the Backend Demo

```bash
python siem_backend.py
```

Example output with the included sample logs:

```text
============================================================
SIEM ENGINE - ALERT SUMMARY
============================================================
Logs Processed: 12
Total Alerts: 5
Open Alerts: 5
Critical Alerts: 1
Resolution Rate: 0.0%
```

Your output may change if you replace `sample_logs.json` with different log data.

### 3. Start the API Server

```bash
python siem_api.py
```

The API runs at:

```text
http://localhost:5000
```

### 4. Open the Dashboard

Open `dashboard.html` in your browser while the API server is running.

The dashboard expects the API at:

```text
http://localhost:5000
```

## Replacing the Sample Logs

To use your own logs, replace `sample_logs.json` with a JSON array using the same schema:

```json
[
  {
    "timestamp": "2026-05-08T10:00:00+04:00",
    "source_ip": "192.168.1.105",
    "event_type": "Authentication",
    "action": "failed",
    "user": "admin",
    "details": "Raw or summarized event details"
  }
]
```

The backend also includes normalization helpers for Splunk/Windows-style records. If using a Splunk export, keep private/raw exports local and sanitize them before committing to a public repository.

## API Endpoints

### Health

```http
GET /api/health
```

### Alerts

```http
GET /api/alerts
GET /api/alerts?severity=high
GET /api/alerts?status=open
GET /api/alerts/<alert_id>
POST /api/alerts/<alert_id>/triage
```

Example triage request:

```bash
curl -X POST http://localhost:5000/api/alerts/ALERT_ID/triage \
  -H "Content-Type: application/json" \
  -d "{\"status\":\"false_positive\",\"notes\":\"Confirmed benign lab activity\"}"
```

### Analytics

```http
GET /api/stats
GET /api/top-threats
GET /api/timeline
GET /api/dashboard-data
```

### Export

```http
GET /api/export?format=json
GET /api/export?format=csv
```

## Windows Event Mapping

The loader can map common Windows Event IDs into SIEM-friendly categories:

| Event ID | Meaning | Normalized Category |
| --- | --- | --- |
| 4624 | Successful logon | Authentication / success |
| 4625 | Failed logon | Authentication / failed |
| 4634 | Logoff | Authentication |
| 4648 | Explicit credential logon | Authentication |
| 4672 | Special privileges assigned | Command Execution / privilege-related |
| 4688 | Process creation | Process Creation |
| 7040 | Service start type changed | Service Change |
| 7045 | New service installed | Service Change |

This mapping can be extended as more lab scenarios are added.

## SOC Skills Demonstrated

- Log analysis and normalization
- Windows Event Log concepts
- Splunk export handling
- Detection rule development
- Alert correlation
- Severity and priority scoring
- Alert triage workflow
- REST API usage
- Dashboard-based investigation
- False positive tuning

## Technologies Used

| Component | Technology |
| --- | --- |
| Detection engine | Python 3 |
| API server | Flask |
| API CORS support | Flask-CORS |
| Dashboard | HTML, CSS, JavaScript |
| Data format | JSON / newline-delimited JSON |
| Tested source logs | Windows Event Logs from VM/Splunk lab |
| Published dataset | Sanitized sample JSON |

## Limitations

This is a portfolio/lab project, so it has some intentional limitations:

- Alerts are stored in memory and reset when the API restarts.
- There is no authentication or analyst account system.
- Detection rules are simple and should be tuned for real environments.
- Threat intelligence is a small local dictionary, not a live feed.
- The dashboard is static HTML and expects the Flask API to run locally.
- Raw lab logs are excluded from GitHub for privacy.

## Troubleshooting

### Flask Is Missing

```bash
pip install -r requirements.txt
```

### Dashboard Shows API Offline

Make sure the Flask API is running:

```bash
python siem_api.py
```

Then test:

```bash
curl http://localhost:5000/api/health
```

### No Logs Are Loaded

Check that the file is named exactly:

```text
sample_logs.json
```

and that it is in the same folder as `siem_backend.py`.

### Too Many False Positives

Tune the detection logic in `siem_backend.py`, especially the Windows Event ID mappings and privilege escalation rule.

## Author

Built by Roseena Shaji as a SOC Analyst L1 portfolio project.

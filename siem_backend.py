"""
SIEM Alert Detection Engine
A real-world SIEM system that ingests logs, applies threat detection rules,
and generates security alerts for triage.

This demonstrates core SOC skills:
- Log parsing and normalization
- Threat pattern detection
- Alert correlation
- Risk scoring
"""

import json
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any
from collections import defaultdict
import re

class SIEMEngine:
    """Core SIEM engine for threat detection and alert generation"""
    
    def __init__(self):
        self.alerts = []
        self.failed_auth_attempts = []
        self.processed_logs = 0
        self.threat_rules = self._initialize_threat_rules()
        self.ip_reputation = self._load_ip_reputation()
        
    def _initialize_threat_rules(self) -> Dict:
        """Define threat detection rules based on MITRE ATT&CK framework"""
        return {
            'brute_force': {
                'threshold': 5,  # 5 failed logins = alert
                'timeframe': 300,  # within 5 minutes
                'severity': 'medium',
                'tactic': 'Credential Access',
                'description': 'Multiple failed authentication attempts detected'
            },
            'suspicious_port_scan': {
                'threshold': 20,  # 20+ connection attempts to different ports
                'timeframe': 60,
                'severity': 'medium',
                'tactic': 'Discovery',
                'description': 'Port scanning activity detected'
            },
            'sql_injection': {
                'patterns': [
                    r"(?i)(union.*select|select.*from|insert.*into|delete.*from|drop.*table)",
                    r"(?i)('.*or.*'=|\".*or.*\"=)",
                    r"(?i)(;.*--|#|\/\*)",
                ],
                'severity': 'high',
                'tactic': 'Exploitation',
                'description': 'SQL injection attempt detected'
            },
            'privilege_escalation': {
                'keywords': ['sudo', 'admin', 'root', 'su -'],
                'severity': 'high',
                'tactic': 'Privilege Escalation',
                'description': 'Potential privilege escalation attempt'
            },
            'data_exfiltration': {
                'threshold': 100,  # 100MB+ data transfer
                'severity': 'critical',
                'tactic': 'Exfiltration',
                'description': 'Unusual data transfer volume detected'
            },
            'malware_indicators': {
                'extensions': ['.exe', '.dll', '.scr', '.bat', '.cmd'],
                'severity': 'critical',
                'tactic': 'Execution',
                'description': 'Executable file detected in suspicious context'
            }
        }
    
    def _load_ip_reputation(self) -> Dict[str, str]:
        """Load known malicious IPs for threat intel correlation"""
        return {
            '192.168.1.105': 'known_attacker',
            '10.0.0.50': 'known_attacker',
            '172.16.0.77': 'suspicious',
        }
    
    def ingest_logs(self, logs: List[Dict]) -> None:
        """
        Ingest and normalize logs from various sources
        Logs should contain: timestamp, source_ip, event_type, user, action, details
        """
        for log in logs:
            self.processed_logs += 1
            self._analyze_log(log)
    
    def _analyze_log(self, log: Dict) -> None:
        """Analyze individual log entry against threat rules"""
        
        # Extract key fields
        source_ip = log.get('source_ip', 'unknown')
        user = log.get('user', 'unknown')
        event_type = log.get('event_type', '').lower()
        action = log.get('action', '').lower()
        details = log.get('details', '')
        timestamp = log.get('timestamp', datetime.now().isoformat())
        
        # Rule 1: Brute Force Detection
        if event_type == 'authentication' and action == 'failed':
            self._check_brute_force(source_ip, user, timestamp)
        
        # Rule 2: SQL Injection Detection
        if any(self._matches_sql_injection(details)):
            self._create_alert(
                'sql_injection',
                source_ip=source_ip,
                user=user,
                timestamp=timestamp,
                details=f"SQL injection detected in: {details[:100]}"
            )
        
        # Rule 3: Privilege Escalation Detection
        if any(kw in action for kw in self.threat_rules['privilege_escalation']['keywords']):
            self._create_alert(
                'privilege_escalation',
                source_ip=source_ip,
                user=user,
                timestamp=timestamp,
                details=f"Privilege escalation attempt: {action}"
            )
        
        # Rule 4: Malware Indicators
        if any(action.endswith(ext) for ext in self.threat_rules['malware_indicators']['extensions']):
            self._create_alert(
                'malware_indicators',
                source_ip=source_ip,
                user=user,
                timestamp=timestamp,
                details=f"Suspicious executable detected: {action}"
            )
        
        # Rule 5: IP Reputation Check
        if source_ip in self.ip_reputation:
            reputation = self.ip_reputation[source_ip]
            severity = 'high' if reputation == 'known_attacker' else 'medium'
            self._create_alert(
                'ip_reputation',
                source_ip=source_ip,
                user=user,
                timestamp=timestamp,
                details=f"Connection from {reputation} IP: {source_ip}",
                severity=severity
            )
    
    def _matches_sql_injection(self, text: str) -> List[bool]:
        """Check if text matches SQL injection patterns"""
        patterns = self.threat_rules['sql_injection']['patterns']
        return [bool(re.search(pattern, text)) for pattern in patterns]
    
    def _check_brute_force(self, source_ip: str, user: str, timestamp: str) -> None:
        """Correlate failed login attempts to detect brute force"""
        rule = self.threat_rules['brute_force']
        
        # Count failed attempts from same IP in timeframe
        time_threshold = datetime.fromisoformat(timestamp) - timedelta(seconds=rule['timeframe'])
        
        failed_attempts = [
            attempt for attempt in self.failed_auth_attempts
            if attempt.get('source_ip') == source_ip
            and attempt.get('user') == user
            and datetime.fromisoformat(attempt.get('timestamp', '')) > time_threshold
        ]
        
        if len(failed_attempts) >= (rule['threshold'] - 1):  # -1 because we're adding this one
            self._create_alert(
                'brute_force',
                source_ip=source_ip,
                user=user,
                timestamp=timestamp,
                details=f"Brute force attack detected: {len(failed_attempts) + 1} failed attempts in {rule['timeframe']}s"
            )
        else:
            # Log failed attempt for correlation
            self.failed_auth_attempts.append({
                'source_ip': source_ip,
                'user': user,
                'timestamp': timestamp
            })
    
    def _create_alert(self, rule_type: str, source_ip: str, user: str, 
                     timestamp: str, details: str, severity: str = None) -> None:
        """Create a security alert"""
        rule = self.threat_rules.get(rule_type, {})
        severity = severity or rule.get('severity', 'medium')
        
        alert = {
            'alert_id': self._generate_alert_id(),
            'timestamp': timestamp,
            'rule_type': rule_type,
            'rule_name': rule.get('description', rule_type),
            'severity': severity,
            'source_ip': source_ip,
            'user': user,
            'details': details,
            'tactic': rule.get('tactic', 'Unknown'),
            'status': 'open',  # SOC analyst will triage this
            'priority_score': self._calculate_priority(severity)
        }
        
        self.alerts.append(alert)
    
    def _generate_alert_id(self) -> str:
        """Generate unique alert ID"""
        timestamp = datetime.now().isoformat()
        return hashlib.md5(f"{timestamp}{len(self.alerts)}".encode()).hexdigest()[:12]
    
    def _calculate_priority(self, severity: str) -> int:
        """Convert severity to priority score (1-10)"""
        severity_map = {
            'low': 2,
            'medium': 5,
            'high': 8,
            'critical': 10
        }
        return severity_map.get(severity, 5)
    
    def get_alerts(self, status: str = None, severity: str = None, 
                   limit: int = None) -> List[Dict]:
        """Retrieve alerts with optional filtering (SOC triage view)"""
        filtered_alerts = self.alerts
        
        if status:
            filtered_alerts = [a for a in filtered_alerts if a.get('status') == status]
        
        if severity:
            filtered_alerts = [a for a in filtered_alerts if a.get('severity') == severity]
        
        # Sort by priority score (highest first) - most critical at top
        filtered_alerts = sorted(filtered_alerts, key=lambda x: x.get('priority_score', 0), reverse=True)
        
        if limit:
            filtered_alerts = filtered_alerts[:limit]
        
        return filtered_alerts
    
    def triage_alert(self, alert_id: str, status: str, notes: str = '') -> bool:
        """
        SOC analyst triages an alert (marks as true positive, false positive, etc.)
        This is core SOC work - deciding if an alert is real or noise
        """
        for alert in self.alerts:
            if alert.get('alert_id') == alert_id:
                alert['status'] = status  # 'investigating', 'resolved', 'false_positive', 'escalated'
                alert['analyst_notes'] = notes
                alert['triage_timestamp'] = datetime.now().isoformat()
                return True
        return False
    
    def get_statistics(self) -> Dict:
        """Return SIEM statistics for dashboard"""
        alerts_by_severity = defaultdict(int)
        alerts_by_rule = defaultdict(int)
        
        for alert in self.alerts:
            alerts_by_severity[alert.get('severity', 'unknown')] += 1
            alerts_by_rule[alert.get('rule_type', 'unknown')] += 1
        
        return {
            'total_logs_processed': self.processed_logs,
            'total_alerts': len(self.alerts),
            'open_alerts': len([a for a in self.alerts if a.get('status') == 'open']),
            'critical_alerts': len([a for a in self.alerts if a.get('severity') == 'critical']),
            'alerts_by_severity': dict(alerts_by_severity),
            'alerts_by_rule': dict(alerts_by_rule),
            'alert_resolution_rate': self._calculate_resolution_rate()
        }
    
    def _calculate_resolution_rate(self) -> float:
        """Calculate percentage of alerts that have been triaged"""
        if not self.alerts:
            return 0.0
        resolved = len([a for a in self.alerts if a.get('status') != 'open'])
        return (resolved / len(self.alerts)) * 100
    
    def export_alerts(self, format: str = 'json') -> str:
        """Export alerts for reporting and compliance"""
        if format == 'json':
            return json.dumps(self.alerts, indent=2, default=str)
        elif format == 'csv':
            # Simplified CSV export
            lines = ['Alert ID,Timestamp,Rule,Severity,Source IP,User,Status']
            for alert in self.alerts:
                lines.append(
                    f"{alert.get('alert_id')},{alert.get('timestamp')},"
                    f"{alert.get('rule_type')},{alert.get('severity')},"
                    f"{alert.get('source_ip')},{alert.get('user')},{alert.get('status')}"
                )
            return '\n'.join(lines)
        return None


# Sample test data generator
def generate_sample_logs() -> List[Dict]:
    """Generate realistic security logs with attack scenarios"""
    base_time = datetime.now()
    logs = []
    
    # Scenario 1: Brute Force Attack (5 failed logins from same IP)
    for i in range(5):
        logs.append({
            'timestamp': (base_time - timedelta(minutes=5-i)).isoformat(),
            'source_ip': '192.168.1.105',
            'event_type': 'Authentication',
            'action': 'failed',
            'user': 'admin',
            'details': 'Invalid password'
        })
    
    # Scenario 2: Successful login after brute force
    logs.append({
        'timestamp': (base_time - timedelta(minutes=1)).isoformat(),
        'source_ip': '192.168.1.105',
        'event_type': 'Authentication',
        'action': 'success',
        'user': 'admin',
        'details': 'Successful login'
    })
    
    # Scenario 3: SQL Injection Attempt
    logs.append({
        'timestamp': base_time.isoformat(),
        'source_ip': '10.0.0.50',
        'event_type': 'HTTP Request',
        'action': 'POST /login',
        'user': 'unknown',
        'details': "username=admin' OR '1'='1&password=anything"
    })
    
    # Scenario 4: Privilege Escalation
    logs.append({
        'timestamp': base_time.isoformat(),
        'source_ip': '172.16.0.1',
        'event_type': 'Command Execution',
        'action': 'sudo cat /etc/shadow',
        'user': 'testuser',
        'details': 'Attempt to read sensitive system file'
    })
    
    # Scenario 5: Malware Execution
    logs.append({
        'timestamp': base_time.isoformat(),
        'source_ip': '172.16.0.50',
        'event_type': 'File Execution',
        'action': 'C:\\Users\\Admin\\Downloads\\payload.exe',
        'user': 'admin',
        'details': 'Executable file executed from user downloads'
    })
    
    # Scenario 6: Suspicious IP Connection
    logs.append({
        'timestamp': base_time.isoformat(),
        'source_ip': '192.168.1.105',
        'event_type': 'Network Connection',
        'action': 'established',
        'user': 'service_account',
        'details': 'Outbound connection to known attacker IP'
    })
    
    # Normal logs (baseline traffic)
    for i in range(20):
        logs.append({
            'timestamp': (base_time - timedelta(minutes=i)).isoformat(),
            'source_ip': f'172.16.0.{100+i}',
            'event_type': 'Authentication',
            'action': 'success',
            'user': f'user{i}',
            'details': 'Normal login'
        })
    
    return logs


def load_logs_from_file(path: str = 'sample_logs.json') -> List[Dict]:
    """
    Load real lab logs from JSON exports.
    Supports both normal JSON arrays and Splunk newline-delimited JSON exports.
    """
    file_path = Path(path)
    if not file_path.exists():
        return generate_sample_logs()

    raw_content = file_path.read_text(encoding='utf-8-sig').strip()
    if not raw_content:
        return []

    records = _parse_log_records(raw_content)
    return [_normalize_log_record(record) for record in records]


def _parse_log_records(raw_content: str) -> List[Dict[str, Any]]:
    """Parse a JSON array, single JSON object, or newline-delimited JSON file."""
    try:
        parsed = json.loads(raw_content)
    except json.JSONDecodeError:
        records = []
        for line in raw_content.splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))
        return records

    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        if isinstance(parsed.get('results'), list):
            return parsed['results']
        return [parsed]
    return []


def _normalize_log_record(record: Dict[str, Any]) -> Dict:
    """Convert Splunk/Windows log records into the SIEM engine's common schema."""
    source = record.get('result', record)

    if {'timestamp', 'source_ip', 'event_type', 'action', 'user', 'details'}.issubset(source):
        return source

    event_code = str(source.get('EventCode', '')).strip()
    log_name = source.get('LogName') or source.get('source') or source.get('sourcetype') or 'Windows Event Log'
    message = source.get('Message') or source.get('_raw') or json.dumps(source, default=str)

    return {
        'timestamp': _normalize_timestamp(source.get('_time') or source.get('TimeCreated') or source.get('timestamp')),
        'source_ip': _first_present(source, [
            'Source_Network_Address',
            'IpAddress',
            'Client_Address',
            'SourceAddress',
            'src_ip',
            'host',
            'ComputerName'
        ]),
        'event_type': _windows_event_type(event_code, log_name),
        'action': _windows_action(event_code, source),
        'user': _first_present(source, [
            'TargetUserName',
            'Account_Name',
            'User',
            'SubjectUserName',
            'Security_ID'
        ]),
        'details': message
    }


def _normalize_timestamp(value: Any) -> str:
    """Return an ISO timestamp that datetime.fromisoformat can parse."""
    if not value:
        return datetime.now().isoformat()

    timestamp = str(value)
    timezone_match = re.search(r'([+-]\d{2})(\d{2})$', timestamp)
    if timezone_match:
        timestamp = f"{timestamp[:-5]}{timezone_match.group(1)}:{timezone_match.group(2)}"
    return timestamp


def _first_present(source: Dict[str, Any], fields: List[str]) -> str:
    """Return the first useful field value from a log record."""
    for field in fields:
        value = source.get(field)
        if value not in (None, '', '-', 'N/A'):
            return str(value)
    return 'unknown'


def _windows_event_type(event_code: str, log_name: str) -> str:
    """Map common Windows Event IDs into broad SIEM event categories."""
    if event_code in {'4624', '4625', '4634', '4648'}:
        return 'Authentication'
    if event_code in {'4688'}:
        return 'Process Creation'
    if event_code in {'4672', '4670', '4907'}:
        return 'Command Execution'
    if event_code in {'7040', '7045'}:
        return 'Service Change'
    return log_name


def _windows_action(event_code: str, source: Dict[str, Any]) -> str:
    """Map Windows Event IDs into actions the detection rules can evaluate."""
    if event_code == '4625':
        return 'failed'
    if event_code == '4624':
        return 'success'
    if event_code == '4672':
        account_name = str(source.get('Account_Name') or source.get('TargetUserName') or '').upper()
        if account_name in {'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'} or account_name.endswith('$'):
            return 'special privileges assigned'
        return 'admin special privileges assigned'
    if event_code == '4688':
        return source.get('New_Process_Name') or source.get('Process_Name') or 'process created'
    if event_code == '7045':
        return 'service installed'
    if event_code == '7040':
        return 'service start type changed'
    return str(source.get('Action') or source.get('OpCode') or source.get('TaskCategory') or event_code or 'unknown')


if __name__ == '__main__':
    # Initialize SIEM engine
    siem = SIEMEngine()
    
    # Ingest sample_logs.json by default; fallback to built-in sample logs if missing.
    logs = load_logs_from_file()
    siem.ingest_logs(logs)
    
    # Display statistics
    print("=" * 60)
    print("SIEM ENGINE - ALERT SUMMARY")
    print("=" * 60)
    stats = siem.get_statistics()
    print(f"Logs Processed: {stats['total_logs_processed']}")
    print(f"Total Alerts: {stats['total_alerts']}")
    print(f"Open Alerts: {stats['open_alerts']}")
    print(f"Critical Alerts: {stats['critical_alerts']}")
    print(f"Resolution Rate: {stats['alert_resolution_rate']:.1f}%")
    print()
    
    # Display top alerts by priority
    print("TOP ALERTS FOR TRIAGE:")
    print("-" * 60)
    top_alerts = siem.get_alerts(status='open', limit=5)
    for alert in top_alerts:
        print(f"\n[{alert['alert_id']}] {alert['rule_name']}")
        print(f"  Severity: {alert['severity'].upper()}")
        print(f"  Source IP: {alert['source_ip']}")
        print(f"  User: {alert['user']}")
        print(f"  Details: {alert['details']}")
    
    print("\n" + "=" * 60)

"""
SIEM API Server
REST API for the SIEM engine - allows dashboard to interact with alerts,
retrieve statistics, and perform triage operations.

This demonstrates how real SIEM platforms (Splunk, ELK) expose APIs
for automated workflows and integrations.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
from siem_backend import SIEMEngine, load_logs_from_file
import json

app = Flask(__name__)
CORS(app)

# Initialize SIEM engine (in production, this would connect to a real data store)
siem = SIEMEngine()
siem.ingest_logs(load_logs_from_file())

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

@app.route('/api/stats', methods=['GET'])
def get_statistics():
    """Get SIEM statistics"""
    stats = siem.get_statistics()
    return jsonify({
        'success': True,
        'data': stats
    })

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """
    Get alerts with optional filtering
    Query parameters:
    - status: open, resolved, false_positive, escalated
    - severity: low, medium, high, critical
    - limit: max number of results
    """
    status = request.args.get('status')
    severity = request.args.get('severity')
    limit = request.args.get('limit', default=50, type=int)
    
    alerts = siem.get_alerts(status=status, severity=severity, limit=limit)
    
    return jsonify({
        'success': True,
        'count': len(alerts),
        'data': alerts
    })

@app.route('/api/alerts/<alert_id>', methods=['GET'])
def get_alert_detail(alert_id):
    """Get detailed information about a specific alert"""
    alert = next((a for a in siem.alerts if a.get('alert_id') == alert_id), None)
    
    if not alert:
        return jsonify({'success': False, 'error': 'Alert not found'}), 404
    
    return jsonify({
        'success': True,
        'data': alert
    })

@app.route('/api/alerts/<alert_id>/triage', methods=['POST'])
def triage_alert(alert_id):
    """
    Triage an alert - SOC analyst marks it as:
    - false_positive (alert was incorrect)
    - investigating (still looking into it)
    - resolved (threat handled)
    - escalated (send to incident response team)
    """
    data = request.get_json()
    status = data.get('status')
    notes = data.get('notes', '')
    
    if not status:
        return jsonify({'success': False, 'error': 'Status required'}), 400
    
    success = siem.triage_alert(alert_id, status, notes)
    
    if success:
        alert = next((a for a in siem.alerts if a.get('alert_id') == alert_id), None)
        return jsonify({
            'success': True,
            'message': f'Alert triaged as {status}',
            'data': alert
        })
    else:
        return jsonify({'success': False, 'error': 'Alert not found'}), 404

@app.route('/api/alerts/severity/<severity>', methods=['GET'])
def get_alerts_by_severity(severity):
    """Get all alerts of a specific severity level"""
    alerts = siem.get_alerts(severity=severity)
    
    return jsonify({
        'success': True,
        'severity': severity,
        'count': len(alerts),
        'data': alerts
    })

@app.route('/api/top-threats', methods=['GET'])
def get_top_threats():
    """
    Get the most common threat types detected
    Useful for identifying patterns and trends
    """
    threat_counts = {}
    for alert in siem.alerts:
        rule_type = alert.get('rule_type', 'unknown')
        threat_counts[rule_type] = threat_counts.get(rule_type, 0) + 1
    
    # Sort by frequency
    sorted_threats = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)
    
    return jsonify({
        'success': True,
        'data': [
            {'threat_type': t[0], 'count': t[1]} 
            for t in sorted_threats
        ]
    })

@app.route('/api/timeline', methods=['GET'])
def get_alert_timeline():
    """Get alerts grouped by time periods (for timeline visualization)"""
    period_map = {}
    
    for alert in siem.alerts:
        # Round to nearest 15 minutes
        timestamp = datetime.fromisoformat(alert.get('timestamp', ''))
        rounded_time = timestamp.replace(minute=(timestamp.minute // 15) * 15, second=0, microsecond=0)
        time_key = rounded_time.isoformat()
        
        if time_key not in period_map:
            period_map[time_key] = {'timestamp': time_key, 'count': 0, 'severity_breakdown': {}}
        
        period_map[time_key]['count'] += 1
        severity = alert.get('severity', 'unknown')
        period_map[time_key]['severity_breakdown'][severity] = period_map[time_key]['severity_breakdown'].get(severity, 0) + 1
    
    timeline = sorted(period_map.values(), key=lambda x: x['timestamp'])
    
    return jsonify({
        'success': True,
        'data': timeline
    })

@app.route('/api/export', methods=['GET'])
def export_alerts():
    """Export alerts in JSON or CSV format"""
    format_type = request.args.get('format', 'json')
    
    if format_type == 'csv':
        data = siem.export_alerts(format='csv')
        return data, 200, {'Content-Disposition': 'attachment; filename=alerts.csv', 'Content-Type': 'text/csv'}
    else:
        data = siem.export_alerts(format='json')
        return data, 200, {'Content-Disposition': 'attachment; filename=alerts.json', 'Content-Type': 'application/json'}

@app.route('/api/dashboard-data', methods=['GET'])
def get_dashboard_data():
    """
    Comprehensive dashboard data endpoint
    Returns everything needed for the SOC dashboard in one request
    """
    stats = siem.get_statistics()
    alerts = siem.get_alerts(limit=20)
    
    # Calculate metrics
    critical_alerts = [a for a in siem.alerts if a.get('severity') == 'critical']
    avg_triage_time = 0  # Would calculate from real data
    
    return jsonify({
        'success': True,
        'timestamp': datetime.now().isoformat(),
        'stats': stats,
        'recent_alerts': alerts,
        'critical_count': len(critical_alerts),
        'avg_triage_time_minutes': avg_triage_time
    })

@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({'success': False, 'error': 'Server error'}), 500

if __name__ == '__main__':
    print("Starting SIEM API Server...")
    print("API Documentation:")
    print("  GET  /api/health - Server health check")
    print("  GET  /api/stats - Overall SIEM statistics")
    print("  GET  /api/alerts - List all alerts (with filtering)")
    print("  GET  /api/alerts/<id> - Get specific alert details")
    print("  POST /api/alerts/<id>/triage - Triage an alert")
    print("  GET  /api/top-threats - Most common threats")
    print("  GET  /api/timeline - Alert timeline")
    print("  GET  /api/export?format=json|csv - Export alerts")
    print("\n")
    app.run(debug=True, port=5000)

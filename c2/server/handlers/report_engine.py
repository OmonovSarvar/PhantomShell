"""Report generator -- produces engagement reports in HTML and JSON."""

import html
import json
import logging
import time
import uuid

log = logging.getLogger("phantom.c2.report")


class ReportEngine:
    """Generates engagement reports from session data."""

    def __init__(self):
        self._reports: dict[str, dict] = {}

    def generate(self, sessions: list[str], session_manager,
                 credential_store, network_map, template: str = "technical",
                 fmt: str = "html") -> dict:
        """Generate a report and store it.

        Args:
            sessions: list of session_ids to include
            session_manager: SessionManager instance
            credential_store: CredentialStore instance
            network_map: NetworkMap instance
            template: executive | technical | findings
            fmt: html | json

        Returns:
            dict with report metadata and content
        """
        report_id = f"rpt-{uuid.uuid4().hex[:8]}"
        report_data = self._collect_data(sessions, session_manager,
                                         credential_store, network_map)

        if template == "executive":
            content = self._render_executive(report_data, fmt)
        elif template == "findings":
            content = self._render_findings(report_data, fmt)
        else:
            content = self._render_technical(report_data, fmt)

        report = {
            "id": report_id,
            "template": template,
            "format": fmt,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "session_count": len(sessions),
            "content": content,
        }
        self._reports[report_id] = report
        log.info(f"[+] Report generated: {report_id} ({template}/{fmt})")
        return report

    def list_reports(self) -> list[dict]:
        return [
            {k: v for k, v in r.items() if k != "content"}
            for r in self._reports.values()
        ]

    def get_report(self, report_id: str) -> dict | None:
        return self._reports.get(report_id)

    # ---- data collection ----

    def _collect_data(self, sessions, session_manager,
                      credential_store, network_map) -> dict:
        """Aggregate data from all sources into a single dict for rendering."""
        sess_data = []
        all_responses = []
        findings = []

        for sid in sessions:
            s = session_manager.get_session(sid)
            if not s:
                continue
            sess_data.append(s.summary)
            # Collect responses that are still stored on the session
            for resp in s.responses:
                all_responses.append(resp)
                finding = self._extract_finding(sid, resp)
                if finding:
                    findings.append(finding)

        credentials = credential_store.list_all() if credential_store else []
        graph = network_map.get_graph() if network_map else {"nodes": [], "edges": []}

        # Calculate engagement duration
        timestamps = []
        for s in sessions:
            sess = session_manager.get_session(s)
            if sess:
                timestamps.append(sess.registered_at)
        start = min(timestamps) if timestamps else time.time()
        duration_hrs = round((time.time() - start) / 3600, 1)

        return {
            "sessions": sess_data,
            "responses": all_responses,
            "findings": findings,
            "credentials": credentials,
            "network": graph,
            "stats": {
                "hosts": len(graph["nodes"]),
                "sessions": len(sess_data),
                "duration_hours": duration_hrs,
                "commands_executed": len(all_responses),
                "credentials_found": len(credentials),
            },
        }

    _PRIVESC_KEYWORDS = ("privilege", "escalat", "root", "admin", "system",
                         "sudo", "suid", "getsystem")
    _VULN_KEYWORDS = ("vuln", "exploit", "cve-", "ms17", "eternalblue",
                      "injection", "overflow", "rce", "lfi", "sqli")

    def _extract_finding(self, session_id: str, response: dict) -> dict | None:
        """Try to extract a security finding from a task response.

        Looks for privesc / AD / steal results and builds a finding dict
        with vuln name, severity, affected host, evidence and remediation.
        """
        output = response.get("output", "")
        command = response.get("command", response.get("task_id", ""))
        if not output:
            return None

        output_lower = output.lower()
        is_privesc = any(kw in output_lower for kw in self._PRIVESC_KEYWORDS)
        is_vuln = any(kw in output_lower for kw in self._VULN_KEYWORDS)
        is_steal = command.startswith("steal_") if isinstance(command, str) else False

        if not (is_privesc or is_vuln or is_steal):
            return None

        if is_steal:
            severity = "High"
            vuln_name = f"Credential Harvesting ({command})"
            remediation = ("Rotate compromised credentials. Enforce MFA. "
                          "Review credential storage practices.")
        elif is_privesc:
            severity = "Critical"
            vuln_name = "Privilege Escalation"
            remediation = ("Patch the vulnerable component. Apply least-privilege "
                          "principles. Monitor for anomalous privilege changes.")
        else:
            severity = "High"
            vuln_name = "Vulnerability Exploited"
            remediation = ("Apply vendor patches. Review network segmentation. "
                          "Implement intrusion detection.")

        return {
            "vulnerability": vuln_name,
            "severity": severity,
            "session": session_id,
            "command": command,
            "evidence": output[:2000],
            "remediation": remediation,
        }

    # ---- renderers ----

    def _render_executive(self, data: dict, fmt: str) -> str:
        if fmt == "json":
            return json.dumps({
                "title": "PhantomShell - Executive Summary",
                "stats": data["stats"],
                "risk_rating": self._risk_rating(data["findings"]),
                "recommendations": self._recommendations(data["findings"]),
                "finding_count": len(data["findings"]),
            }, indent=2)

        stats = data["stats"]
        risk = self._risk_rating(data["findings"])
        recs = self._recommendations(data["findings"])

        return self._html_wrap("Executive Summary", f"""
        <div class="section">
            <h2>Engagement Overview</h2>
            <table>
                <tr><td>Duration</td><td>{stats['duration_hours']} hours</td></tr>
                <tr><td>Hosts Discovered</td><td>{stats['hosts']}</td></tr>
                <tr><td>Sessions Established</td><td>{stats['sessions']}</td></tr>
                <tr><td>Findings</td><td>{len(data['findings'])}</td></tr>
                <tr><td>Credentials Harvested</td><td>{stats['credentials_found']}</td></tr>
                <tr><td>Overall Risk</td><td class="risk-{risk.lower()}">{risk}</td></tr>
            </table>
        </div>
        <div class="section">
            <h2>Recommendations</h2>
            <ul>{''.join(f'<li>{html.escape(r)}</li>' for r in recs)}</ul>
        </div>
        """)

    def _render_technical(self, data: dict, fmt: str) -> str:
        """Full technical report: methodology, findings, timeline, network."""
        if fmt == "json":
            return json.dumps({
                "title": "PhantomShell - Technical Report",
                "stats": data["stats"],
                "sessions": data["sessions"],
                "findings": data["findings"],
                "credentials": [
                    {k: v for k, v in c.items() if k != "password"}
                    for c in data["credentials"]
                ],
                "network": data["network"],
                "timeline": self._build_timeline(data),
            }, indent=2)

        stats = data["stats"]
        timeline = self._build_timeline(data)

        findings_html = ""
        for i, f in enumerate(data["findings"], 1):
            evidence = html.escape(f["evidence"][:500])
            findings_html += f"""
            <div class="finding">
                <h3>Finding {i}: {html.escape(f['vulnerability'])}</h3>
                <p><strong>Severity:</strong>
                    <span class="risk-{f['severity'].lower()}">{f['severity']}</span></p>
                <p><strong>Session:</strong> {html.escape(f['session'])}</p>
                <p><strong>Evidence:</strong></p>
                <pre>{evidence}</pre>
                <p><strong>Remediation:</strong> {html.escape(f['remediation'])}</p>
            </div>"""

        creds_html = ""
        for c in data["credentials"]:
            creds_html += (
                f"<tr><td>{html.escape(c['type'])}</td>"
                f"<td>{html.escape(c['username'])}</td>"
                f"<td>{html.escape(c['host'])}</td>"
                f"<td>{html.escape(c['source'])}</td></tr>"
            )

        timeline_html = ""
        for t in timeline[:100]:
            timeline_html += (
                f"<tr><td>{html.escape(t['time'])}</td>"
                f"<td>{html.escape(t['session'])}</td>"
                f"<td>{html.escape(t['action'])}</td></tr>"
            )

        return self._html_wrap("Technical Report", f"""
        <div class="section">
            <h2>Engagement Statistics</h2>
            <table>
                <tr><td>Duration</td><td>{stats['duration_hours']} hours</td></tr>
                <tr><td>Hosts</td><td>{stats['hosts']}</td></tr>
                <tr><td>Sessions</td><td>{stats['sessions']}</td></tr>
                <tr><td>Commands Executed</td><td>{stats['commands_executed']}</td></tr>
                <tr><td>Credentials</td><td>{stats['credentials_found']}</td></tr>
            </table>
        </div>
        <div class="section">
            <h2>Findings ({len(data['findings'])})</h2>
            {findings_html if findings_html else '<p>No findings extracted.</p>'}
        </div>
        <div class="section">
            <h2>Credentials</h2>
            <table>
                <tr><th>Type</th><th>Username</th><th>Host</th><th>Source</th></tr>
                {creds_html if creds_html else '<tr><td colspan="4">None</td></tr>'}
            </table>
        </div>
        <div class="section">
            <h2>Timeline</h2>
            <table>
                <tr><th>Time</th><th>Session</th><th>Action</th></tr>
                {timeline_html if timeline_html else '<tr><td colspan="3">No activity</td></tr>'}
            </table>
        </div>
        <div class="section">
            <h2>Network Map</h2>
            <p>Nodes: {len(data['network']['nodes'])},
               Edges: {len(data['network']['edges'])}</p>
        </div>
        """)

    def _render_findings(self, data: dict, fmt: str) -> str:
        if fmt == "json":
            return json.dumps({
                "title": "PhantomShell - Findings Report",
                "findings": data["findings"],
            }, indent=2)

        findings_html = ""
        for i, f in enumerate(data["findings"], 1):
            evidence = html.escape(f["evidence"][:500])
            findings_html += f"""
            <div class="finding">
                <h3>{i}. {html.escape(f['vulnerability'])}</h3>
                <p><strong>Severity:</strong>
                    <span class="risk-{f['severity'].lower()}">{f['severity']}</span></p>
                <p><strong>Affected Session:</strong> {html.escape(f['session'])}</p>
                <p><strong>Evidence:</strong></p>
                <pre>{evidence}</pre>
                <p><strong>Remediation:</strong> {html.escape(f['remediation'])}</p>
            </div>"""

        return self._html_wrap("Findings Report", f"""
        <div class="section">
            <h2>Security Findings ({len(data['findings'])})</h2>
            {findings_html if findings_html else '<p>No findings extracted from session data.</p>'}
        </div>
        """)

    # ---- helpers ----

    def _risk_rating(self, findings: list[dict]) -> str:
        if not findings:
            return "Low"
        severities = [f["severity"] for f in findings]
        if "Critical" in severities:
            return "Critical"
        if "High" in severities:
            return "High"
        return "Medium"

    def _recommendations(self, findings: list[dict]) -> list[str]:
        recs = set()
        for f in findings:
            recs.add(f["remediation"])
        if not recs:
            recs.add("Continue monitoring. No critical findings at this time.")
        return sorted(recs)

    def _build_timeline(self, data: dict) -> list[dict]:
        timeline = []
        for resp in data["responses"]:
            ts = resp.get("timestamp", 0)
            timeline.append({
                "time": time.strftime("%Y-%m-%d %H:%M:%S",
                                     time.localtime(ts)) if ts else "N/A",
                "session": resp.get("session_id", "?"),
                "action": resp.get("command",
                                   resp.get("task_id", "unknown")),
            })
        timeline.sort(key=lambda x: x["time"])
        return timeline

    def _html_wrap(self, title: str, body: str) -> str:
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhantomShell - {html.escape(title)}</title>
<style>
    body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 0; padding: 20px;
           background: #0a0a0a; color: #e0e0e0; }}
    h1 {{ color: #ff4444; border-bottom: 2px solid #ff4444; padding-bottom: 10px; }}
    h2 {{ color: #ff6666; }}
    .section {{ background: #1a1a1a; border: 1px solid #333; border-radius: 8px;
                padding: 20px; margin: 20px 0; }}
    table {{ width: 100%; border-collapse: collapse; }}
    td, th {{ padding: 8px 12px; border-bottom: 1px solid #333; text-align: left; }}
    th {{ color: #ff4444; }}
    pre {{ background: #111; padding: 12px; border-radius: 4px; overflow-x: auto;
           font-size: 13px; }}
    .finding {{ border-left: 4px solid #ff4444; padding-left: 16px; margin: 16px 0; }}
    .risk-critical {{ color: #ff0000; font-weight: bold; }}
    .risk-high {{ color: #ff6600; font-weight: bold; }}
    .risk-medium {{ color: #ffaa00; }}
    .risk-low {{ color: #00cc00; }}
    .footer {{ text-align: center; color: #666; margin-top: 40px; font-size: 12px; }}
</style>
</head>
<body>
<h1>PhantomShell // {html.escape(title)}</h1>
{body}
<div class="footer">
    Generated by PhantomShell C2 &mdash; {time.strftime('%Y-%m-%d %H:%M:%S')}
</div>
</body>
</html>"""

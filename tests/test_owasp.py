import asyncio

from backend.main import active_scans, get_scan_status
from backend.config import settings
from backend.models import OWASPScanResult, RiskLevel, OWASPScanResponse, ScanStatus
from backend.owasp_scanner import OWASPScanner


def test_is_safe_target_rejects_non_http_scheme():
	scanner = OWASPScanner()
	ok, message = scanner._is_safe_target("ftp://example.com")

	assert ok is False
	assert "HTTP/HTTPS" in message


def test_is_safe_target_rejects_internal_ips(monkeypatch):
	scanner = OWASPScanner()
	monkeypatch.setattr(settings, "BLOCK_INTERNAL_IPS", True)
	monkeypatch.setattr("socket.gethostbyname", lambda _: "127.0.0.1")

	ok, message = scanner._is_safe_target("http://example.com")

	assert ok is False
	assert "internal IP" in message


def test_run_scan_builds_expected_summary(monkeypatch):
	scanner = OWASPScanner()
	progress_updates = []

	monkeypatch.setattr(scanner, "_is_safe_target", lambda _: (True, "OK"))

	sql_result = OWASPScanResult(
		vulnerability_id="A03:2021-SQLi-001",
		title="Potential SQL Injection in URL Parameter",
		category="A03:2021-Injection",
		severity=RiskLevel.HIGH,
		description="Possible SQL injection",
		remediation="Use prepared statements"
	)

	xss_result = OWASPScanResult(
		vulnerability_id="A03:2021-XSS-001",
		title="Potential Reflected XSS",
		category="A03:2021-Injection",
		severity=RiskLevel.MEDIUM,
		description="Possible reflected XSS",
		remediation="Encode output"
	)

	monkeypatch.setattr(scanner, "scan_sql_injection", lambda _: [sql_result])
	monkeypatch.setattr(scanner, "scan_xss", lambda _: [xss_result])
	monkeypatch.setattr(scanner, "scan_broken_auth", lambda _: [])
	monkeypatch.setattr(scanner, "scan_access_control", lambda _: [])
	monkeypatch.setattr(scanner, "scan_misconfiguration", lambda _: [])
	monkeypatch.setattr(scanner, "scan_ssrf", lambda _: [])

	response = scanner.run_scan(
		"https://example.com",
		scan_depth="basic",
		include_remediation=True,
		progress_callback=lambda progress, message: progress_updates.append((progress, message)),
	)

	assert response.vulnerabilities_found == 2
	assert response.summary["high"] == 1
	assert response.summary["medium"] == 1
	assert len(response.remediation_summary) == 2
	assert progress_updates
	assert progress_updates[-1][0] == 0.98


def test_get_scan_status_returns_completed_result_payload():
	scan_id = "scan-complete-test"
	active_scans[scan_id] = ScanStatus(
		scan_id=scan_id,
		status="completed",
		progress=1.0,
		message="Scan completed",
		result=OWASPScanResponse(
			target_url="https://example.com",
			scan_duration_seconds=0.5,
			vulnerabilities_found=0,
			results=[],
			summary={"low": 0, "medium": 0, "high": 0, "critical": 0},
			remediation_summary=[],
		),
	)

	try:
		data = asyncio.run(get_scan_status(scan_id))

		assert data.vulnerabilities_found == 0
		assert not hasattr(data, "status")
	finally:
		active_scans.pop(scan_id, None)

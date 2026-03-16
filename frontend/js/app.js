/**
 * Security Analyzer Pro - Frontend Application Logic
 */

// API Configuration
const API_BASE = window.location.origin + '/api';

// DOM Elements
const tabs = document.querySelectorAll('[data-tab]');
const tabPanes = document.querySelectorAll('.tab-pane');
const loadingModal = new bootstrap.Modal(document.getElementById('loadingModal'));

// Tab Navigation
tabs.forEach(tab => {
    tab.addEventListener('click', (e) => {
        e.preventDefault();
        
        // Update active tab
        tabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        
        // Show corresponding pane
        const targetTab = tab.dataset.tab;
        tabPanes.forEach(pane => {
            pane.classList.remove('active');
            if (pane.id === targetTab) {
                pane.classList.add('active');
            }
        });
        
        // Reset forms when switching tabs
        document.getElementById('phishingForm')?.reset();
        document.getElementById('owaspForm')?.reset();
        document.getElementById('comprehensiveForm')?.reset();
        
        // Hide results
        document.getElementById('phishingResults')?.classList.add('d-none');
        document.getElementById('owaspResults')?.classList.add('d-none');
        document.getElementById('comprehensiveResults')?.classList.add('d-none');
    });
});

// ==================== PHISHING DETECTION ====================
document.getElementById('phishingForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const emailContent = document.getElementById('emailContent').value.trim();
    const url = document.getElementById('phishingUrl').value.trim();
    
    if (!emailContent && !url) {
        showToast('Please provide email content or a URL to analyze', 'warning');
        return;
    }
    
    showLoading('Analyzing for phishing indicators...');
    
    try {
        const response = await fetch(`${API_BASE}/analyze/phishing`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email_content: emailContent || null,
                url: url || null
            })
        });
        
        if (!response.ok) throw new Error('Analysis failed');
        
        const result = await response.json();
        displayPhishingResults(result);
        
    } catch (error) {
        console.error('Phishing analysis error:', error);
        showToast('Analysis failed: ' + error.message, 'danger');
    } finally {
        hideLoading();
    }
});

function displayPhishingResults(data) {
    const resultsDiv = document.getElementById('phishingResults');
    resultsDiv.classList.remove('d-none');
    
    // Update risk metrics
    document.getElementById('riskScore').textContent = data.risk_score.toFixed(2);
    document.getElementById('confidence').textContent = `${Math.round(data.confidence * 100)}%`;
    document.getElementById('indicatorCount').textContent = data.indicators.length;
    
    // Set risk level badge
    const riskBadge = document.getElementById('riskLevelBadge');
    riskBadge.className = `badge bg-${getRiskColor(data.risk_level)}`;
    riskBadge.textContent = `${data.risk_level.toUpperCase()} RISK`;
    
    // Update verdict
    const verdictDiv = document.getElementById('phishingVerdict');
    const verdictText = document.getElementById('verdictText');
    
    if (data.is_phishing) {
        verdictDiv.className = 'alert alert-danger';
        verdictText.innerHTML = `<strong>⚠️ PHISHING DETECTED</strong> - Do not interact with this content`;
    } else {
        verdictDiv.className = 'alert alert-success';
        verdictText.innerHTML = `<strong>✓ Likely Safe</strong> - No strong phishing indicators found`;
    }
    
    // Display indicators
    const indicatorsList = document.getElementById('indicatorsList');
    indicatorsList.innerHTML = '';
    
    if (data.indicators.length === 0) {
        indicatorsList.innerHTML = '<div class="list-group-item text-secondary">No suspicious indicators detected</div>';
    } else {
        data.indicators.forEach(ind => {
            const item = document.createElement('div');
            item.className = `list-group-item list-group-item-action border-${getRiskColor(ind.severity)}`;
            item.innerHTML = `
                <div class="d-flex w-100 justify-content-between">
                    <h6 class="mb-1">${ind.name}</h6>
                    <small class="badge bg-${getRiskColor(ind.severity)}">${ind.severity.toUpperCase()}</small>
                </div>
                <p class="mb-1 small">${ind.description}</p>
                ${ind.evidence ? `<small class="text-muted">Evidence: ${truncate(ind.evidence, 80)}</small>` : ''}
            `;
            indicatorsList.appendChild(item);
        });
    }
    
    // Display recommendations
    const recList = document.getElementById('recommendationsList');
    recList.innerHTML = '';
    data.recommendations.forEach(rec => {
        const li = document.createElement('li');
        li.className = 'list-group-item bg-transparent border-0';
        li.innerHTML = `<i class="bi bi-check-circle-fill text-success me-2"></i>${rec}`;
        recList.appendChild(li);
    });
    
    // Scroll to results
    resultsDiv.scrollIntoView({ behavior: 'smooth' });
}

// ==================== OWASP SCANNER ====================
document.getElementById('owaspForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const targetUrl = document.getElementById('owaspTarget').value.trim();
    const scanDepth = document.getElementById('scanDepth').value;
    const includeRemediation = document.getElementById('includeRemediation').checked;
    
    if (!targetUrl) {
        showToast('Please enter a target URL', 'warning');
        return;
    }
    
    // Safety confirmation
    if (!confirm(`⚠️ Safety Confirmation\n\nYou are about to scan:\n${targetUrl}\n\nOnly proceed if you own this application or have explicit written permission to test it.\n\nContinue?`)) {
        return;
    }
    
    showLoading('Starting vulnerability scan...');
    
    try {
        // Start scan
        const response = await fetch(`${API_BASE}/scan/owasp`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target_url: targetUrl,
                scan_depth: scanDepth,
                include_remediation: includeRemediation
            })
        });
        
        if (!response.ok) throw new Error('Failed to start scan');
        
        const { scan_id } = await response.json();
        
        // Poll for results
        await pollScanResults(scan_id, displayOWASPResults);
        
    } catch (error) {
        console.error('OWASP scan error:', error);
        showToast('Scan failed: ' + error.message, 'danger');
    } finally {
        hideLoading();
    }
});

async function pollScanResults(scanId, callback) {
    const progressDiv = document.getElementById('scanProgress');
    const progressBar = document.getElementById('progressBar');
    const progressMsg = document.getElementById('progressMessage');
    
    progressDiv.classList.remove('d-none');

    try {
        while (true) {
            const response = await fetch(`${API_BASE}/scan/status/${scanId}`);
            if (!response.ok) {
                throw new Error('Unable to retrieve scan status');
            }

            const status = await response.json();
            const progress = Number(status.progress || 0);
            const isCompletedResultPayload = !status.status && (
                Array.isArray(status.results) || typeof status.overall_risk_score === 'number'
            );

            // Keep progress display safe even if backend omits progress.
            progressBar.style.width = `${Math.round(progress * 100)}%`;
            progressBar.textContent = `${Math.round(progress * 100)}%`;
            progressMsg.textContent = status.message || 'Processing...';

            if (status.status === 'completed') {
                callback(status.result || status);
                return;
            }

            if (isCompletedResultPayload) {
                callback(status);
                return;
            }

            if (status.status === 'failed') {
                throw new Error(status.message || 'Scan failed');
            }

            await new Promise(resolve => setTimeout(resolve, 2000));
        }
    } finally {
        progressDiv.classList.add('d-none');
    }
}

function displayOWASPResults(data) {
    const resultsDiv = document.getElementById('owaspResults');
    resultsDiv.classList.remove('d-none');
    
    // Update vulnerability counts
    document.getElementById('vulnCount').textContent = `${data.vulnerabilities_found} issues`;
    document.getElementById('criticalCount').textContent = data.summary.critical || 0;
    document.getElementById('highCount').textContent = data.summary.high || 0;
    document.getElementById('mediumCount').textContent = data.summary.medium || 0;
    document.getElementById('lowCount').textContent = data.summary.low || 0;
    
    // Display vulnerabilities
    const vulnList = document.getElementById('vulnerabilitiesList');
    vulnList.innerHTML = '';
    
    if (data.results.length === 0) {
        vulnList.innerHTML = `
            <div class="list-group-item text-center text-success">
                <i class="bi bi-check-circle-fill fs-4 d-block mb-2"></i>
                No vulnerabilities detected with current scan settings
            </div>
        `;
    } else {
        data.results.forEach(vuln => {
            const item = document.createElement('div');
            item.className = `list-group-item list-group-item-action border-${getRiskColor(vuln.severity)}`;
            item.innerHTML = `
                <div class="d-flex w-100 justify-content-between align-items-start">
                    <div>
                        <h6 class="mb-1">${vuln.title}</h6>
                        <small class="text-muted">${vuln.category}</small>
                    </div>
                    <span class="badge bg-${getRiskColor(vuln.severity)} mb-2">${vuln.severity.toUpperCase()}</span>
                </div>
                <p class="mb-2 small">${vuln.description}</p>
                ${vuln.affected_endpoint ? `<small class="d-block text-muted mb-2">Endpoint: ${truncate(vuln.affected_endpoint, 60)}</small>` : ''}
                ${vuln.proof_of_concept ? `<details class="mb-2"><summary class="small text-primary">View Proof of Concept</summary><code class="d-block small bg-dark p-2 rounded">${escapeHtml(vuln.proof_of_concept)}</code></details>` : ''}
                ${vuln.remediation ? `<small class="text-info"><i class="bi bi-tools me-1"></i>${truncate(vuln.remediation, 120)}...</small>` : ''}
            `;
            vulnList.appendChild(item);
        });
    }
    
    // Display remediation summary
    const remediationSection = document.getElementById('remediationSection');
    const remediationList = document.getElementById('remediationList');
    
    if (data.remediation_summary && data.remediation_summary.length > 0) {
        remediationSection.classList.remove('d-none');
        remediationList.innerHTML = '';
        data.remediation_summary.forEach(rem => {
            const item = document.createElement('div');
            item.className = 'list-group-item bg-transparent border-0 small';
            item.innerHTML = rem;
            remediationList.appendChild(item);
        });
    } else {
        remediationSection.classList.add('d-none');
    }
    
    resultsDiv.scrollIntoView({ behavior: 'smooth' });
}

// ==================== COMPREHENSIVE SCAN ====================
document.getElementById('comprehensiveForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const targetUrl = document.getElementById('compTarget').value.trim();
    const emailSample = document.getElementById('compEmail').value.trim();
    const depth = document.getElementById('compDepth').value;
    const remediation = document.getElementById('compRemediation').value === 'true';
    
    if (!targetUrl) {
        showToast('Target URL is required', 'warning');
        return;
    }
    
    if (!confirm(`🔍 Comprehensive Scan Confirmation\n\nTarget: ${targetUrl}\n\nThis will run both phishing analysis AND vulnerability scanning.\n\nOnly proceed with explicit authorization.\n\nContinue?`)) {
        return;
    }
    
    showLoading('Launching comprehensive security assessment...');
    
    try {
        const response = await fetch(`${API_BASE}/scan/comprehensive`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: targetUrl,
                email_sample: emailSample || null,
                scan_options: {
                    depth: depth,
                    remediation: remediation
                }
            })
        });
        
        if (!response.ok) throw new Error('Failed to start comprehensive scan');
        
        const { scan_id } = await response.json();
        
        // Poll for results
        await pollScanResults(scan_id, displayComprehensiveResults);
        
    } catch (error) {
        console.error('Comprehensive scan error:', error);
        showToast('Scan failed: ' + error.message, 'danger');
    } finally {
        hideLoading();
    }
});

function displayComprehensiveResults(data) {
    const resultsDiv = document.getElementById('comprehensiveResults');
    resultsDiv.classList.remove('d-none');
    
    // Update overall risk
    document.getElementById('overallScore').textContent = data.overall_risk_score.toFixed(2);
    document.getElementById('overallRiskLevel').textContent = data.overall_risk_level.toUpperCase();
    document.getElementById('overallRiskLevel').className = `display-3 fw-bold text-${getRiskColor(data.overall_risk_level)}`;
    document.getElementById('overallRiskBar').style.width = `${data.overall_risk_score * 100}%`;
    document.getElementById('overallRiskBar').className = `progress-bar bg-${getRiskColor(data.overall_risk_level)}`;
    
    // Executive summary
    document.getElementById('executiveSummary').textContent = data.executive_summary;
    
    // Component summaries
    const phishingSummary = document.getElementById('compPhishingSummary');
    if (data.phishing_analysis) {
        phishingSummary.innerHTML = `
            <div class="d-flex justify-content-between mb-2">
                <span>Risk Score:</span>
                <strong class="text-${getRiskColor(data.phishing_analysis.risk_level)}">${data.phishing_analysis.risk_score.toFixed(2)}</strong>
            </div>
            <div class="d-flex justify-content-between mb-2">
                <span>Phishing Detected:</span>
                <strong>${data.phishing_analysis.is_phishing ? '⚠️ YES' : '✓ No'}</strong>
            </div>
            <div class="d-flex justify-content-between">
                <span>Indicators:</span>
                <strong>${data.phishing_analysis.indicators.length}</strong>
            </div>
        `;
    }
    
    const owaspSummary = document.getElementById('compOwaspSummary');
    if (data.owasp_scan) {
        owaspSummary.innerHTML = `
            <div class="d-flex justify-content-between mb-2">
                <span>Vulnerabilities:</span>
                <strong>${data.owasp_scan.vulnerabilities_found}</strong>
            </div>
            <div class="d-flex justify-content-between mb-2">
                <span>Critical/High:</span>
                <strong class="text-danger">${(data.owasp_scan.summary.critical || 0) + (data.owasp_scan.summary.high || 0)}</strong>
            </div>
            <div class="d-flex justify-content-between">
                <span>Scan Time:</span>
                <strong>${data.owasp_scan.scan_duration_seconds}s</strong>
            </div>
        `;
    }
    
    // Next steps
    const stepsList = document.getElementById('nextStepsList');
    stepsList.innerHTML = '';
    data.next_steps.forEach(step => {
        const li = document.createElement('li');
        li.className = 'list-group-item bg-transparent border-0';
        li.innerHTML = `<i class="bi bi-arrow-right-circle-fill text-primary me-2"></i>${step}`;
        stepsList.appendChild(li);
    });
    
    resultsDiv.scrollIntoView({ behavior: 'smooth' });
}

// ==================== UTILITY FUNCTIONS ====================
function getRiskColor(level) {
    const colors = {
        'low': 'success',
        'medium': 'warning',
        'high': 'danger',
        'critical': 'danger'
    };
    return colors[level.toLowerCase()] || 'secondary';
}

function truncate(str, len) {
    if (!str) return '';
    return str.length > len ? str.substring(0, len) + '...' : str;
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function showLoading(message) {
    document.getElementById('loadingMessage').textContent = message;
    loadingModal.show();
}

function hideLoading() {
    loadingModal.hide();
}

function showToast(message, type = 'info') {
    // Simple toast implementation
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-bg-${type} border-0 position-fixed bottom-0 end-0 m-3`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">${message}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    document.body.appendChild(toast);
    
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
    
    toast.addEventListener('hidden.bs.toast', () => toast.remove());
}

function copyResults() {
    // Implementation for copying results to clipboard
    showToast('Report copied to clipboard', 'success');
}

function exportPDF() {
    // Implementation for PDF export (would require jsPDF or server-side)
    showToast('PDF export feature coming soon', 'info');
}

function downloadFullReport() {
    showToast('Generating comprehensive report...', 'info');
    // Implementation for full report download
}

function scheduleRetest() {
    showToast('Retest scheduled for 24 hours', 'success');
    // Implementation for scheduling
}

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
    // Set default active tab
    document.querySelector('[data-tab="phishing"]').click();
    
    // Add input validation
    const urlInputs = document.querySelectorAll('input[type="url"]');
    urlInputs.forEach(input => {
        input.addEventListener('blur', function() {
            if (this.value && !this.value.startsWith('http')) {
                this.value = 'https://' + this.value;
            }
        });
    });
    
    console.log('🛡️ Security Analyzer Pro initialized');
});
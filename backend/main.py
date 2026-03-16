"""
FastAPI Application - Security Analyzer Backend
Fully Fixed Version
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
import uuid
import os
from datetime import datetime
from typing import Optional, Dict, Any

# Ensure imports match the folder structure
from backend.config import settings, get_settings
from backend.models import (
    PhishingAnalysisRequest, OWAPScanRequest, ComprehensiveScanRequest,
    PhishingAnalysisResponse, OWASPScanResponse, ComprehensiveScanResponse,
    ScanStatus, RiskLevel, Indicator
)
from backend.phishing_detector import detector
# Note: You need to create backend/owasp_scanner.py similarly if it doesn't exist
# For now, assuming it exists or mocking it for the fix
try:
    from backend.owasp_scanner import scanner
except ImportError:
    class MockScanner:
        def run_scan(self, target_url, scan_depth, include_remediation):
            return OWASPScanResponse(
                target_url=target_url,
                scan_duration_seconds=0.1,
                vulnerabilities_found=0,
                results=[],
                summary={},
                remediation_summary=["No scanner configured"]
            )
    scanner = MockScanner()

# Initialize FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI-Powered Phishing Detection & OWASP Vulnerability Scanner",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory scan tracking
active_scans: Dict[str, Any] = {}

# ==================== API ROUTES ====================
@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/analyze/phishing")
async def analyze_phishing(request: PhishingAnalysisRequest):
    """Analyze email content or URL for phishing indicators"""
    try:
        if not request.email_content and not request.url:
            raise HTTPException(status_code=400, detail="Either email_content or url must be provided")
        
        result = detector.analyze(
            email_content=request.email_content,
            url=request.url,
            headers=request.headers,
            from_address=request.headers.get("From") if request.headers else None
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        print(f"Phishing analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/scan/owasp")
async def start_owasp_scan(request: OWAPScanRequest, background_tasks: BackgroundTasks):
    """Start an OWASP vulnerability scan (async)"""
    scan_id = str(uuid.uuid4())
    active_scans[scan_id] = ScanStatus(
        scan_id=scan_id,
        status="pending",
        progress=0.0,
        message="Scan queued"
    )

    def run_scan():
        try:
            active_scans[scan_id].status = "running"
            active_scans[scan_id].progress = 0.2
            active_scans[scan_id].message = "Initializing scanner..."

            def update_progress(progress: float, message: str):
                active_scans[scan_id].progress = progress
                active_scans[scan_id].message = message
            
            result = scanner.run_scan(
                target_url=request.target_url,
                scan_depth=request.scan_depth,
                include_remediation=request.include_remediation,
                progress_callback=update_progress
            )
            
            active_scans[scan_id].status = "completed"
            active_scans[scan_id].progress = 1.0
            active_scans[scan_id].message = "Scan completed"
            active_scans[scan_id].result = result
            
        except ValueError as e:
            active_scans[scan_id].status = "failed"
            active_scans[scan_id].message = f"Validation error: {str(e)}"
        except Exception as e:
            active_scans[scan_id].status = "failed"
            active_scans[scan_id].message = f"Scan error: {str(e)}"

    background_tasks.add_task(run_scan)
    return {"scan_id": scan_id, "status": "queued", "message": "Scan started"}

@app.get("/api/scan/status/{scan_id}")
async def get_scan_status(scan_id: str):
    """Check the status of a running scan"""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    status = active_scans[scan_id]

    if status.status == "completed" and hasattr(status, "result"):
        return status.result

    return status.dict()

@app.post("/api/scan/comprehensive")
async def comprehensive_scan(request: ComprehensiveScanRequest, background_tasks: BackgroundTasks):
    """Run both phishing analysis and OWASP scan"""
    scan_id = str(uuid.uuid4())
    active_scans[scan_id] = ScanStatus(scan_id=scan_id, status="pending", progress=0.0)

    def run_comprehensive():
        try:
            active_scans[scan_id].status = "running"
            
            active_scans[scan_id].progress = 0.3
            active_scans[scan_id].message = "Analyzing for phishing indicators..."
            phishing_result = detector.analyze(url=request.url, email_content=request.email_sample)
            
            active_scans[scan_id].progress = 0.7
            active_scans[scan_id].message = "Scanning for vulnerabilities..."

            def update_progress(progress: float, message: str):
                active_scans[scan_id].progress = 0.7 + (progress * 0.3)
                active_scans[scan_id].message = message

            owasp_result = scanner.run_scan(
                target_url=request.url,
                scan_depth=request.scan_options.get("depth", "basic"),
                include_remediation=request.scan_options.get("remediation", True),
                progress_callback=update_progress
            )
            
            phishing_risk = phishing_result.risk_score
            owasp_risk = min(1.0, owasp_result.vulnerabilities_found * 0.15)
            overall_score = round((phishing_risk + owasp_risk) / 2, 2)
            
            if overall_score >= 0.8:
                overall_level = "critical"
            elif overall_score >= 0.5:
                overall_level = "high"
            elif overall_score >= 0.2:
                overall_level = "medium"
            else:
                overall_level = "low"
            
            summary_parts = []
            if phishing_result.is_phishing:
                summary_parts.append(f"⚠️ Phishing risk detected (score: {phishing_result.risk_score})")
            if owasp_result.vulnerabilities_found > 0:
                summary_parts.append(f"🔍 {owasp_result.vulnerabilities_found} vulnerabilities found")
            if not summary_parts:
                summary_parts.append("✓ No immediate threats detected")
            
            active_scans[scan_id].status = "completed"
            active_scans[scan_id].progress = 1.0
            
            # Convert string level to Enum for the model
            level_enum = RiskLevel(overall_level)

            active_scans[scan_id].result = ComprehensiveScanResponse(
                phishing_analysis=phishing_result,
                owasp_scan=owasp_result,
                overall_risk_score=overall_score,
                overall_risk_level=level_enum,
                executive_summary="; ".join(summary_parts),
                next_steps=[
                    "Review detailed findings in each section",
                    "Prioritize remediation based on severity",
                    "Retest after applying fixes",
                    "Implement continuous monitoring"
                ]
            )
            
        except Exception as e:
            active_scans[scan_id].status = "failed"
            active_scans[scan_id].message = str(e)

    background_tasks.add_task(run_comprehensive)
    return {"scan_id": scan_id, "status": "queued"}

# ==================== FRONTEND SERVING ====================
if os.path.exists("frontend"):
    if os.path.exists("frontend/css"):
        app.mount("/css", StaticFiles(directory="frontend/css"), name="css")
    if os.path.exists("frontend/js"):
        app.mount("/js", StaticFiles(directory="frontend/js"), name="js")

    @app.get("/")
    async def serve_frontend():
        return FileResponse("frontend/index.html")
else:
    @app.get("/")
    async def frontend_not_found():
        return {"message": "Frontend not found", "api_docs": "/api/docs"}

# ==================== ERROR HANDLERS ====================
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "timestamp": datetime.utcnow().isoformat()}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    print(f"Unhandled error: {exc}")
    import traceback
    traceback.print_exc()
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "timestamp": datetime.utcnow().isoformat()}
    )

if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info"
    )
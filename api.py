"""FastAPI backend (optional).   Run:  uvicorn api:app --host 127.0.0.1 --port 8000
Interactive docs: http://127.0.0.1:8000/docs
All responses use one shape:  {"ok": bool, "data": {...} | null, "error": "..." | null}
"""
import logging

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

import config
from ai.explainer import explain
from scanners.image_scanner import scan_image
from scanners.login_scanner import analyze_logins, load_login_csv
from scanners.message_scanner import scan_message
from scanners.url_scanner import scan_url
from services import history
from utils.validation import validate_csv_upload

log = logging.getLogger("trustshield")
app = FastAPI(title="TrustShield AI API", version="1.0",
              description="Automated indicators-based scam assessments. Not a definitive fraud determination.")
app.add_middleware(CORSMiddleware, allow_origins=config.CORS_ORIGINS, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])
MAX_BODY = config.MAX_UPLOAD_BYTES + 64 * 1024


def envelope(ok, data=None, error=None, status=200):
    return JSONResponse({"ok": ok, "data": data, "error": error}, status_code=status)


@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_BODY:
        return envelope(False, error="Request too large.", status=413)
    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def _validation(_, exc):
    return envelope(False, error="Invalid request. Check the field names and sizes.", status=422)


@app.exception_handler(StarletteHTTPException)
async def _http(_, exc):
    return envelope(False, error=str(exc.detail), status=exc.status_code)


@app.exception_handler(Exception)
async def _unexpected(_, exc):
    log.error("Unhandled error: %s", type(exc).__name__)  # type only: no content, no stack trace to the client
    return envelope(False, error="Internal error.", status=500)


class UrlIn(BaseModel):
    url: str = Field(..., max_length=config.MAX_URL_CHARS)
    use_model: bool = True


class MessageIn(BaseModel):
    body: str = Field(..., max_length=config.MAX_TEXT_CHARS)
    sender: str = Field("", max_length=320)
    subject: str = Field("", max_length=500)


def _finish(result, scan_type):
    if not result.get("ok"):
        return envelope(False, error=result["error"], status=400)
    result["explanation"] = explain(result)  # template only; LLM use is a UI-level, consented choice
    history.add_scan(scan_type, result["risk_category"], result["risk_score"], result.get("summary", ""))
    return envelope(True, result)


@app.get("/api/health")
def health():
    from ai.predictor import load_model
    bundle, why = load_model()
    return envelope(True, {"status": "ok", "model_loaded": bundle is not None, "model_note": why})


@app.post("/api/scan/url")
def api_url(item: UrlIn):
    return _finish(scan_url(item.url, use_model=item.use_model), "url")


@app.post("/api/scan/message")
def api_message(item: MessageIn):
    return _finish(scan_message(item.body, sender=item.sender, subject=item.subject), "message")


@app.post("/api/scan/image")
async def api_image(file: UploadFile = File(...)):
    data = await file.read(config.MAX_UPLOAD_BYTES + 1)  # never read more than the limit + 1 byte
    return _finish(scan_image(file.filename, file.content_type, data), "image")


@app.post("/api/scan/login")
async def api_login(file: UploadFile = File(...)):
    data = await file.read(config.MAX_CSV_BYTES + 1)
    err = validate_csv_upload(file.filename, data)
    if err:
        return envelope(False, error=err, status=400)
    try:
        df = analyze_logins(load_login_csv(data))
    except ValueError as e:
        return envelope(False, error=str(e), status=400)
    flagged = df[df["risk_score"] >= 30]
    history.add_scan("login", "High Risk" if (df["risk_score"] >= 60).any() else "Suspicious" if len(flagged) else "Low Risk",
                     int(df["risk_score"].max()), f"{len(flagged)} flagged of {len(df)} events")
    return envelope(True, {"events": len(df), "flagged": len(flagged), "results": flagged.astype(str).to_dict("records")[:200]})


@app.get("/api/history")
def api_history(limit: int = 50):
    return envelope(True, {"scans": history.list_scans(limit), "stats": history.stats()})

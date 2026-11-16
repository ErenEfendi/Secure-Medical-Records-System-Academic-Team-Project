# server/main.py
import os
import hashlib  # <--- NEW IMPORT
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from server.database import Session, User
from server.routes import auth_routes, file_routes, log_routes, req_routes
from server.routes.log_routes import log_access

from security.log_injections import InjectionError

app = FastAPI(title="Secure Medical Records")

@app.exception_handler(InjectionError)
async def injection_handler(request: Request, exc: InjectionError):
    # This forces the response to be Plain Text
    return PlainTextResponse(content=str(exc.message), status_code=400)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

# 1. Mount Static Files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# 2. Routers
app.include_router(auth_routes.router, prefix="/auth")
app.include_router(file_routes.router, prefix="/files")
app.include_router(log_routes.router, prefix="/logs")
app.include_router(req_routes.router, prefix="/req")

# --- MIDDLEWARE ---

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    
    # CSP: Allow 'blob:' for PDF viewer and 'data:' for images
    csp_policy = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "frame-src 'self' blob:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none';"
    )
    response.headers["Content-Security-Policy"] = csp_policy
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    return response

@app.middleware("http")
async def log_requests(request: Request, call_next):
    resp = await call_next(request)
    log_access(f"{request.client.host} {request.method} {request.url.path} HTTP/1.1 {resp.status_code}")
    return resp

# --- ROUTES ---

def _read_html(name: str) -> str:
    p = os.path.join(STATIC_DIR, name)
    if not os.path.isfile(p):
        raise HTTPException(404, "Not found")
    with open(p, "r", encoding="utf-8") as f:
        return f.read()

# Root Route (Protects index.html)
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    token = request.cookies.get("ssd_token")
    if not token:
        return RedirectResponse("/login.html", status_code=302)

    # FIX: Hash the token from the cookie before checking DB
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    sess = Session()
    # Check against the HASHED token
    user = sess.query(User).filter(User.token == token_hash).first()
    sess.close()
    
    if not user:
        return RedirectResponse("/login.html", status_code=302)

    return HTMLResponse(_read_html("index.html"))

@app.get("/index.html", response_class=HTMLResponse)
async def index_page(request: Request):
    return await root(request) 

@app.get("/login.html", response_class=HTMLResponse)
async def login_page():    
    return HTMLResponse(_read_html("login.html"))

@app.get("/register.html", response_class=HTMLResponse)
async def register_page(): 
    return HTMLResponse(_read_html("register.html"))

@app.get("/logout")
async def logout():
    r = RedirectResponse("/login.html", status_code=302)
    r.delete_cookie("ssd_token")
    return r

import threading
def start_monitor():
    try:
        from server import monitor
        t = threading.Thread(target=monitor.monitor, daemon=True)
        t.start()
    except Exception as e:
        print(f"[Monitor] Could not start log monitor: {e}")

start_monitor()

if __name__ == "__main__":
    uvicorn.run(
        "server.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
        ssl_keyfile="pki/certs/server_key.pem",
        ssl_certfile="pki/certs/server_chain.pem"
    )
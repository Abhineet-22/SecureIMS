import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .audit import request_ip
from .config import get_settings
from .db import Base, SessionLocal, engine
from .errors import BusinessError
from .models import Policy
from .ratelimit import limit
from .routes import admin, auth, inventory, reports, students, transactions

log = logging.getLogger("inventory")
settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(engine)  # hackathon shortcut; use Alembic migrations in production
    with SessionLocal() as db:
        if db.get(Policy, 1) is None:
            db.add(Policy(id=1))
            db.commit()
    yield


app = FastAPI(
    title="Department Inventory & Issue Management", version="1.0", lifespan=lifespan,
    docs_url=None if settings.is_prod else "/docs", redoc_url=None, openapi_url=None if settings.is_prod else "/openapi.json",
    dependencies=[Depends(limit("global"))],
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts + (["testserver"] if not settings.is_prod else []))
if settings.cors_origins:
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
                       allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"], allow_headers=["Authorization", "Content-Type"], max_age=600)

_SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",  # relaxed automatically for /docs below
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Cache-Control": "no-store", "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cross-Origin-Resource-Policy": "same-site",
}


@app.middleware("http")
async def hardening(request: Request, call_next):
    rid = uuid.uuid4().hex[:12]
    request_ip.set(request.client.host if request.client else None)  # X-Forwarded-For is NOT trusted by default
    cl = request.headers.get("content-length")
    if cl and (not cl.isdigit() or int(cl) > settings.max_body_bytes):
        return JSONResponse({"detail": "Request body too large"}, status_code=413)
    if request.method in ("POST", "PUT", "PATCH") and "chunked" in request.headers.get("transfer-encoding", "").lower():
        return JSONResponse({"detail": "Chunked uploads are not accepted"}, status_code=411)
    resp = await call_next(request)
    for k, v in _SEC_HEADERS.items():
        if k == "Content-Security-Policy" and request.url.path.startswith(("/docs", "/openapi")):
            continue
        resp.headers.setdefault(k, v)
    resp.headers["X-Request-ID"] = rid
    if "server" in resp.headers:
        del resp.headers["server"]
    return resp


@app.exception_handler(BusinessError)
async def _biz(_: Request, e: BusinessError):
    return JSONResponse({"detail": e.message, "reasons": e.reasons}, status_code=e.status)


@app.exception_handler(RequestValidationError)
async def _val(_: Request, e: RequestValidationError):
    # report field + message only; never echo the submitted values back
    return JSONResponse({"detail": [{"field": ".".join(str(p) for p in err["loc"] if p != "body"), "msg": err["msg"]} for err in e.errors()]}, status_code=422)


@app.exception_handler(StarletteHTTPException)
async def _http(_: Request, e: StarletteHTTPException):
    return JSONResponse({"detail": e.detail}, status_code=e.status_code, headers=getattr(e, "headers", None))


@app.exception_handler(Exception)
async def _unhandled(request: Request, e: Exception):
    log.exception("unhandled error on %s %s", request.method, request.url.path)  # details to server log only
    return JSONResponse({"detail": "Internal server error"}, status_code=500)


@app.get("/", include_in_schema=False)
def root():
    if not settings.is_prod:
        return RedirectResponse(url="/docs")
    return {"status": "ok"}


@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}


for r in (auth.router, admin.router, students.router, inventory.router, transactions.router, transactions.me, reports.router):
    app.include_router(r)

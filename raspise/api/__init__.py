"""API package — builds the FastAPI app with all routes."""
import time
import threading

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from raspise.api.routes import router
from raspise.config import get_config
from raspise.radius.freeradius_routes import router as freeradius_router


# ---------------------------------------------------------------------------
# Per-IP API rate limiter (token-bucket)
# ---------------------------------------------------------------------------

class APIRateLimitMiddleware(BaseHTTPMiddleware):
    """Limits requests per IP across all API endpoints.

    Default: 120 requests per minute.  The /auth/login endpoint has its
    own stricter limiter in routes.py, so this acts as a broad safety net.
    """

    def __init__(self, app, requests_per_minute: int = 120):
        super().__init__(app)
        self._rpm = requests_per_minute
        self._window = 60.0
        self._buckets: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    async def dispatch(self, request: Request, call_next):
        ip = request.client.host if request.client else "0.0.0.0"
        now = time.monotonic()
        cutoff = now - self._window

        with self._lock:
            timestamps = self._buckets.get(ip, [])
            timestamps = [t for t in timestamps if t > cutoff]
            if len(timestamps) >= self._rpm:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"detail": "Rate limit exceeded. Try again later."},
                )
            timestamps.append(now)
            self._buckets[ip] = timestamps

        return await call_next(request)


def create_api_app() -> FastAPI:
    cfg = get_config()
    app = FastAPI(
        title="RaspISE REST API",
        version="1.0.0",
        description="Cisco ISE-like NAC/AAA REST API",
    )
    app.add_middleware(APIRateLimitMiddleware, requests_per_minute=120)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            f"http://localhost:{cfg.web.port}",
            f"http://127.0.0.1:{cfg.web.port}",
        ],
        allow_origin_regex=r"http://192\.168\.\d+\.\d+:" + str(cfg.web.port),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router)
    app.include_router(freeradius_router)
    return app


api_app = create_api_app()

__all__ = ["api_app", "create_api_app"]

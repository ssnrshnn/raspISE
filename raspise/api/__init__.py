"""API package — builds the FastAPI app with all routes."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from raspise.api.routes import router


def create_api_app() -> FastAPI:
    app = FastAPI(
        title="RaspISE REST API",
        version="1.0.0",
        description="Cisco ISE-like NAC/AAA REST API",
    )
    app.add_middleware(
        CORSMiddleware,
        # Proxy on :8080 calls us from 127.0.0.1; allow that origin plus
        # direct browser access from the local network.
        allow_origins=["http://localhost:8080", "http://127.0.0.1:8080"],
        allow_origin_regex=r"http://192\.168\.\d+\.\d+:8080",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router)
    return app


api_app = create_api_app()

__all__ = ["api_app", "create_api_app"]

"""API package — builds the FastAPI app with all routes."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from raspise.api.routes import router
from raspise.config import get_config
from raspise.radius.freeradius_routes import router as freeradius_router


def create_api_app() -> FastAPI:
    cfg = get_config()
    app = FastAPI(
        title="RaspISE REST API",
        version="1.0.0",
        description="Cisco ISE-like NAC/AAA REST API",
    )
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

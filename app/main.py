from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.v1.api import api_router
from app.api.v1.endpoints.health import health_check
from app.core.config import settings

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=__version__,
    debug=settings.DEBUG,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS Middleware (Foundation configuration)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Top-level health check endpoint for orchestrators / root probes
app.add_api_route("/health", health_check, methods=["GET"], tags=["Health"], summary="Root Health Check")

# Include Versioned API Routes
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/", tags=["Root"], summary="Root status")
async def root():
    return {
        "message": f"Welcome to {settings.PROJECT_NAME} API",
        "docs": "/docs",
        "health": "/health",
        "version": __version__,
    }

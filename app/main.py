from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.v1.api import api_router
from app.api.v1.endpoints.health import health_check
from app.core.config import settings

# Initialize FastAPI application
# In production or when DEBUG is False, interactive documentation endpoints are disabled.
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=__version__,
    debug=settings.DEBUG,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
)

# Configurable CORS Middleware
# Only register middleware if allowed origins are explicitly defined.
# Replaces permissive allow_origins=["*"] wildcard with configurable, environment-aware origin lists.
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.BACKEND_CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Accept"],
    )

# Top-level health check endpoint for orchestrators / root probes
app.add_api_route(
    "/health",
    health_check,
    methods=["GET"],
    tags=["Health"],
    summary="Root Health Check",
)

# Include Versioned API Routes
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/", tags=["Root"], summary="Root status")
async def root():
    response = {
        "message": f"Welcome to {settings.PROJECT_NAME} API",
        "health": "/health",
        "version": __version__,
    }
    if settings.DEBUG:
        response["docs"] = "/docs"
    return response

"""
RedStrike.AI - Main FastAPI Application
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import logging

from app.core.config import settings
from app.core.database import init_db, async_session_maker
from app.core.security import get_password_hash
from app.models import User, UserRole
from app.api import (
    auth_router,
    projects_router,
    findings_router,
    endpoints_router,
    websocket_router,
)
from sqlalchemy import select

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    import secrets
    import string
    
    # Startup
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    
    # Initialize database
    await init_db()
    logger.info("Database initialized")
    
    # Create admin user if not exists
    async with async_session_maker() as db:
        result = await db.execute(
            select(User).where(User.email == settings.admin_email)
        )
        admin = result.scalar_one_or_none()
        
        if not admin:
            # Generate random password if using default
            admin_password = settings.admin_password
            password_generated = False
            
            if admin_password in ["changeme123", "", None]:
                # Generate secure random password
                alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
                admin_password = ''.join(secrets.choice(alphabet) for _ in range(16))
                password_generated = True
            
            admin = User(
                email=settings.admin_email,
                hashed_password=get_password_hash(admin_password),
                role=UserRole.ADMIN,
            )
            db.add(admin)
            await db.commit()
            
            # Show credentials in terminal
            logger.info("=" * 60)
            logger.info("🔐 ADMIN ACCOUNT CREATED")
            logger.info("=" * 60)
            logger.info(f"   Email:    {settings.admin_email}")
            logger.info(f"   Password: {admin_password}")
            if password_generated:
                logger.info("   ⚠️  SAVE THIS PASSWORD - it won't be shown again!")
            logger.info("=" * 60)
    
    yield
    
    # Shutdown
    logger.info("Shutting down...")


# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Enterprise-grade web pentesting agentic application",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router)
app.include_router(projects_router)
app.include_router(findings_router)
app.include_router(endpoints_router)
app.include_router(websocket_router)

# Serve frontend static files
try:
    app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
except Exception:
    logger.warning("Frontend directory not found, skipping static file serving")


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "app": settings.app_name,
        "version": settings.app_version,
    }


@app.get("/api/config")
async def get_config():
    """Get public configuration."""
    return {
        "app_name": settings.app_name,
        "version": settings.app_version,
        "proxy_enabled": settings.proxy_enabled,
        "proxy_port": settings.proxy_port,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.app_host,
        port=settings.app_port,
        reload=settings.debug,
    )

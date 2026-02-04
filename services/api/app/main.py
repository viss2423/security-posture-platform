from fastapi import FastAPI
from .routers import health, assets, jobs, findings, posture

app = FastAPI(title="Security Posture Platform API")

app.include_router(health.router)
app.include_router(assets.router)
app.include_router(posture.router)
app.include_router(jobs.router, prefix="/jobs", tags=["jobs"])
app.include_router(findings.router, prefix="/findings", tags=["findings"])

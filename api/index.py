"""
MailSentinel AI - Ultra-minimal test
"""
from fastapi import FastAPI

app = FastAPI()

@app.get("/api/ping")
@app.get("/ping")
def ping():
    return {"status": "ok", "message": "Vercel Python runtime is working"}

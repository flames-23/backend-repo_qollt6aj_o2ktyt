import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List

import jwt
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, StreamingResponse
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from user_agents import parse as parse_ua
import qrcode
from io import BytesIO
import dns.resolver

from database import db

APP_NAME = "ShortlyX"
JWT_SECRET = os.getenv("JWT_SECRET", "devsecret")
JWT_EXPIRES_HOURS = int(os.getenv("JWT_EXPIRES_HOURS", "72"))
DEFAULT_DOMAIN = os.getenv("DEFAULT_DOMAIN", "")  # optional branding domain for building links

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title=APP_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------- Utility & Auth --------------------

class TokenData(BaseModel):
    user_id: str
    email: EmailStr


def create_jwt(user_id: str, email: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRES_HOURS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def get_current_user(authorization: Optional[str] = Header(None)) -> Optional[Dict[str, Any]]:
    """Decode a Bearer token and return the user document by email.
    We store the subject as string but rely on email for lookup to avoid ObjectId parsing issues.
    """
    if not authorization:
        return None
    try:
        scheme, token = authorization.split(" ")
        if scheme.lower() != "bearer":
            return None
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        email = data.get("email")
        if not email:
            return None
        user = db["user"].find_one({"email": email})
        return user
    except Exception:
        return None


# Mongo helpers
from bson import ObjectId

def by_id_str(id_str: str):
    try:
        return {"_id": ObjectId(id_str)}
    except Exception:
        return {"_id": id_str}


# -------------------- Schemas --------------------

class RegisterBody(BaseModel):
    name: Optional[str] = None
    email: EmailStr
    password: str

class LoginBody(BaseModel):
    email: EmailStr
    password: str

class ShortenBody(BaseModel):
    url: str
    alias: Optional[str] = None
    expires_in_days: Optional[int] = None
    password: Optional[str] = None
    one_time: bool = False
    device_targets: Optional[Dict[str, str]] = None  # desktop/mobile/ios/android
    domain: Optional[str] = None
    title: Optional[str] = None

class DomainBody(BaseModel):
    domain: str

class VerifyDomainBody(BaseModel):
    domain: str

# -------------------- Auth Endpoints --------------------

@app.post("/api/auth/register")
def register(body: RegisterBody):
    existing = db["user"].find_one({"email": body.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already in use")
    hashed = pwd_context.hash(body.password)
    user_doc = {
        "name": body.name,
        "email": body.email.lower(),
        "password_hash": hashed,
        "provider": "local",
        "is_verified": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["user"].insert_one(user_doc)
    token = create_jwt(str(res.inserted_id), body.email.lower())
    return {"token": token, "user": {"id": str(res.inserted_id), "email": body.email.lower(), "name": body.name}}

@app.post("/api/auth/login")
def login(body: LoginBody):
    user = db["user"].find_one({"email": body.email.lower()})
    if not user or not user.get("password_hash"):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not pwd_context.verify(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_jwt(str(user["_id"]), user["email"])
    return {"token": token, "user": {"id": str(user["_id"]), "email": user["email"], "name": user.get("name")}}

# -------------------- Shorten & Links --------------------

import random
import string

def gen_code(n: int = 7) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


def build_short_url(code: str, domain: Optional[str] = None) -> str:
    host = DEFAULT_DOMAIN or os.getenv("FRONTEND_URL", "")
    if domain:
        base = f"https://{domain}"
    elif host:
        base = host.rstrip("/")
    else:
        base = ""
    path = f"/r/{code}"
    return f"{base}{path}" if base else path


RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 30
_rate_map: Dict[str, List[float]] = {}

def rate_limit(ip: str):
    now = datetime.now().timestamp()
    arr = _rate_map.get(ip, [])
    arr = [t for t in arr if now - t < RATE_LIMIT_WINDOW]
    if len(arr) >= RATE_LIMIT_MAX:
        raise HTTPException(status_code=429, detail="Too many requests. Please slow down.")
    arr.append(now)
    _rate_map[ip] = arr

@app.post("/api/shorten")
def api_shorten(body: ShortenBody, request: Request):
    rate_limit(request.client.host if request.client else "unknown")
    # Validate alias uniqueness
    code = body.alias or gen_code(7)
    if db["link"].find_one({"code": code}):
        raise HTTPException(status_code=400, detail="Alias already in use")

    expires_at = None
    if body.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_in_days)

    # Guests: default 7-day expiry if not specified
    current = get_current_user(request.headers.get("authorization"))
    if not current and not expires_at:
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    password_hash = pwd_context.hash(body.password) if body.password else None

    link_doc = {
        "owner_id": str(current.get("_id")) if current else None,
        "original_url": body.url,
        "code": code,
        "domain": body.domain,
        "title": body.title,
        "expires_at": expires_at,
        "password_hash": password_hash,
        "one_time": body.one_time or False,
        "disabled": False,
        "device_targets": body.device_targets or {},
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "clicks": 0,
    }
    db["link"].insert_one(link_doc)
    short_url = build_short_url(code, body.domain)
    return {"short_url": short_url, "code": code}

@app.get("/api/links")
def list_links(authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    items = list(db["link"].find({"owner_id": str(user["_id"])}, {"password_hash": 0}))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return {"links": items}

class UpdateLinkBody(BaseModel):
    title: Optional[str] = None
    original_url: Optional[str] = None
    alias: Optional[str] = None
    expires_at: Optional[datetime] = None
    one_time: Optional[bool] = None
    disabled: Optional[bool] = None
    device_targets: Optional[Dict[str, str]] = None
    password: Optional[str] = None

@app.patch("/api/links/{link_id}")
def update_link(link_id: str, body: UpdateLinkBody, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    link = db["link"].find_one(by_id_str(link_id))
    if not link or link.get("owner_id") != str(user["_id"]):
        raise HTTPException(status_code=404, detail="Not found")
    update = {}
    for k in ["title", "original_url", "expires_at", "one_time", "disabled", "device_targets"]:
        v = getattr(body, k)
        if v is not None:
            update[k] = v
    if body.alias:
        if db["link"].find_one({"code": body.alias, "_id": {"$ne": link["_id"]}}):
            raise HTTPException(status_code=400, detail="Alias already in use")
        update["code"] = body.alias
    if body.password is not None:
        update["password_hash"] = pwd_context.hash(body.password) if body.password else None
    if update:
        update["updated_at"] = datetime.now(timezone.utc)
        db["link"].update_one({"_id": link["_id"]}, {"$set": update})
    return {"ok": True}

@app.delete("/api/links/{link_id}")
def delete_link(link_id: str, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    link = db["link"].find_one(by_id_str(link_id))
    if not link or link.get("owner_id") != str(user["_id"]):
        raise HTTPException(status_code=404, detail="Not found")
    db["link"].delete_one({"_id": link["_id"]})
    db["click"].delete_many({"link_id": str(link["_id"])})
    return {"ok": True}

# -------------------- Redirect & Analytics --------------------

class AccessBody(BaseModel):
    password: Optional[str] = None

@app.get("/r/{code}")
async def redirect(code: str, request: Request, ua: Optional[str] = Header(None)):
    link = db["link"].find_one({"code": code})
    if not link or link.get("disabled"):
        raise HTTPException(status_code=404, detail="Link not found")

    # Expiry
    if link.get("expires_at") and datetime.now(timezone.utc) > link["expires_at"]:
        raise HTTPException(status_code=410, detail="Link expired")

    # Device specific
    user_agent = ua or request.headers.get("user-agent", "")
    parsed = parse_ua(user_agent)
    device_type = "desktop"
    if parsed.is_mobile:
        device_type = "mobile"
    elif parsed.is_tablet:
        device_type = "tablet"
    dest = link.get("device_targets", {}).get(device_type) or link.get("original_url")

    # Password protected → check query param p if present
    p = request.query_params.get("p")
    if link.get("password_hash"):
        if not p or not pwd_context.verify(p, link["password_hash"]):
            raise HTTPException(status_code=401, detail="Password required")

    # One-time link
    if link.get("one_time"):
        # delete link after first open
        db["link"].delete_one({"_id": link["_id"]})

    # Record click
    try:
        db["click"].insert_one({
            "link_id": str(link["_id"]),
            "code": link["code"],
            "ip": request.client.host if request.client else None,
            "country": None,  # GeoIP not configured; can integrate later
            "device": device_type,
            "browser": f"{parsed.browser.family}",
            "os": f"{parsed.os.family}",
            "referer": request.headers.get("referer"),
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        })
        db["link"].update_one({"_id": link["_id"]}, {"$inc": {"clicks": 1}})
    except Exception:
        pass

    return RedirectResponse(dest)

# -------------------- Analytics APIs --------------------

@app.get("/api/links/{code}/analytics")
def link_analytics(code: str, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    link = db["link"].find_one({"code": code})
    if not link:
        raise HTTPException(status_code=404, detail="Not found")
    if link.get("owner_id") and (not user or str(user["_id"]) != link["owner_id"]):
        raise HTTPException(status_code=403, detail="Forbidden")
    clicks = list(db["click"].find({"link_id": str(link["_id"])}))
    def bucket(field: str):
        agg: Dict[str, int] = {}
        for c in clicks:
            k = (c.get(field) or "Unknown").title()
            agg[k] = agg.get(k, 0) + 1
        return sorted([{"label": k, "count": v} for k, v in agg.items()], key=lambda x: -x["count"])[:20]
    return {
        "total_clicks": len(clicks),
        "by_device": bucket("device"),
        "by_browser": bucket("browser"),
        "by_os": bucket("os"),
        "by_country": bucket("country"),
    }

@app.get("/api/me/stats")
def me_stats(authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    uid = str(user["_id"])
    total_links = db["link"].count_documents({"owner_id": uid})
    clicks = list(db["click"].find({"link_id": {"$in": [str(l["_id"]) for l in db["link"].find({"owner_id": uid})]}}))
    total_clicks = len(clicks)
    # last 7 days chart
    today = datetime.now(timezone.utc).date()
    daily = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        start = datetime.combine(day, datetime.min.time(), tzinfo=timezone.utc)
        end = start + timedelta(days=1)
        count = db["click"].count_documents({"created_at": {"$gte": start, "$lt": end}, "link_id": {"$in": [str(l["_id"]) for l in db["link"].find({"owner_id": uid})]}})
        daily.append({"date": day.isoformat(), "clicks": count})
    return {"total_links": total_links, "total_clicks": total_clicks, "daily": daily}

# -------------------- QR Codes --------------------

@app.get("/api/links/{code}/qr")
def qr_png(code: str):
    link = db["link"].find_one({"code": code})
    if not link:
        raise HTTPException(status_code=404, detail="Not found")
    url = build_short_url(code, link.get("domain"))
    img = qrcode.make(url)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")

# -------------------- Domains --------------------

@app.post("/api/domains")
def add_domain(body: DomainBody, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = gen_code(16)
    doc = {
        "owner_id": str(user["_id"]),
        "domain": body.domain.lower(),
        "verification_token": token,
        "verified": False,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    db["domain"].insert_one(doc)
    return {"domain": body.domain.lower(), "token": token, "txt_record": f"_verify.{body.domain.lower()} -> {token}"}

@app.get("/api/domains")
def list_domains(authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    items = list(db["domain"].find({"owner_id": str(user["_id"]) }))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return {"domains": items}

@app.post("/api/domains/verify")
def verify_domain(body: VerifyDomainBody, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    doc = db["domain"].find_one({"owner_id": str(user["_id"]), "domain": body.domain.lower()})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    try:
        txt_name = f"_verify.{body.domain.lower()}"
        answers = dns.resolver.resolve(txt_name, 'TXT', lifetime=3)
        tokens = []
        for rdata in answers:
            tokens.append(b"".join(rdata.strings).decode("utf-8"))
        verified = doc.get("verification_token") in tokens
        db["domain"].update_one({"_id": doc["_id"]}, {"$set": {"verified": bool(verified), "updated_at": datetime.now(timezone.utc)}})
        return {"verified": bool(verified), "checked": tokens}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"DNS check failed: {str(e)[:80]}")

# -------------------- Root & Health --------------------

@app.get("/")
def root():
    return {"name": APP_NAME, "status": "ok"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

import os
import base64
import time
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from nacl.public import PublicKey, SealedBox
from nacl.encoding import Base64Encoder
import jwt
import secrets
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import DuplicateKeyError

# ---- Config (env or defaults) ----
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ISSUER = "harborseal"
JWT_EXP_SECONDS = 3600  # 1 hour
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://mongodb:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "harborseal")

# MongoDB connection
client = None
db = None

DEMO_USER_ID = "u_1"

async def connect_to_mongo():
    """Create database connection"""
    global client, db
    client = AsyncIOMotorClient(MONGODB_URL)
    db = client[DATABASE_NAME]
    
    # Create indexes
    await db.devices.create_index("device_id", unique=True)
    await db.stores.create_index("store_id", unique=True)
    await db.api_keys.create_index("api_key", unique=True)
    await db.users.create_index("user_id", unique=True)
    
    # Bootstrap demo user
    try:
        await db.users.insert_one({
            "user_id": DEMO_USER_ID,
            "email": "demo@example.com",
            "devices": [],
            "stores": []
        })
        await db.api_keys.insert_one({
            "api_key": "demo-api-key",
            "user_id": DEMO_USER_ID
        })
    except DuplicateKeyError:
        pass  # Already exists

async def close_mongo_connection():
    """Close database connection"""
    if client:
        client.close()

# ---- Models ----
class ApiKeyRequest(BaseModel):
    device_id: str

class ApiKeyResponse(BaseModel):
    api_key: str

class RegisterDeviceRequest(BaseModel):
    device_id: str
    public_key_b64: str  # Curve25519 public key (32 bytes) Base64

class RegisterDeviceResponse(BaseModel):
    device_id: str
    jwt: str

class CreateStoreRequest(BaseModel):
    name: str

class StoreResponse(BaseModel):
    store_id: str
    name: str

class WrappedKeyResponse(BaseModel):
    store_id: str
    device_id: str
    wrapped_dek_b64: str

class AddDeviceToStoreRequest(BaseModel):
    device_id: str

# ---- Auth helpers ----
async def require_user(authorization: str = Header(..., alias="Authorization")) -> str:
    # Demo supports either "Bearer <api_key>" OR "DeviceJWT <jwt>"
    try:
        scheme, token = authorization.split(" ", 1)
    except ValueError:
        raise HTTPException(401, "Invalid Authorization header")

    if scheme.lower() == "bearer":
        api_key_doc = await db.api_keys.find_one({"api_key": token})
        if not api_key_doc:
            raise HTTPException(401, "Invalid API key")
        return api_key_doc["user_id"]

    if scheme.lower() == "devicejwt":
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], options={"require": ["sub","iss","exp"]})
            if payload.get("iss") != JWT_ISSUER:
                raise HTTPException(401, "Bad issuer")
            # sub = "user_id:device_id"
            sub = payload["sub"]
            user_id, device_id = sub.split(":")
            # basic check device exists
            device_doc = await db.devices.find_one({"device_id": device_id})
            if not device_doc or device_doc["user_id"] != user_id:
                raise HTTPException(401, "Unknown device")
            return user_id
        except jwt.ExpiredSignatureError:
            raise HTTPException(401, "JWT expired")
        except Exception as e:
            raise HTTPException(401, f"JWT error: {e}")

    raise HTTPException(401, "Unsupported auth scheme")

def issue_device_jwt(user_id: str, device_id: str) -> str:
    now = int(time.time())
    payload = {
        "iss": JWT_ISSUER,
        "sub": f"{user_id}:{device_id}",
        "iat": now,
        "exp": now + JWT_EXP_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

# ---- App ----
app = FastAPI(title="HarborSeal KMS API")

@app.on_event("startup")
async def startup_event():
    await connect_to_mongo()

@app.on_event("shutdown")
async def shutdown_event():
    await close_mongo_connection()

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    print(f"DEBUG: Validation error: {exc.errors()}")
    print(f"DEBUG: Request body: {exc.body}")
    return JSONResponse(
        status_code=400,
        content={"detail": exc.errors(), "body": str(exc.body)}
    )

@app.get("/health")
async def health_check():
    try:
        # Test MongoDB connection
        await db.command("ping")
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database unhealthy: {e}")

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log request details for debugging"""
    if request.method == "POST":
        body = await request.body()
        print(f"DEBUG: {request.method} {request.url.path}")
        print(f"DEBUG: Headers: {dict(request.headers)}")
        print(f"DEBUG: Body: {body.decode() if body else 'Empty'}")
        # Need to recreate request with body for downstream
        from starlette.requests import Request as StarletteRequest
        request = StarletteRequest(request.scope, receive=lambda: {"type": "http.request", "body": body})
    response = await call_next(request)
    return response

@app.post("/apiKey", response_model=ApiKeyResponse)
async def get_api_key(req: ApiKeyRequest):
    """Generate an API key for device registration - allows automatic device onboarding."""
    print(f"DEBUG: Received apiKey request: {req}")
    # For demo purposes, we'll associate the device_id with the demo user
    # In production, this might involve additional verification or user association logic
    api_key = f"auto-{secrets.token_hex(16)}"
    await db.api_keys.insert_one({
        "api_key": api_key,
        "user_id": DEMO_USER_ID,
        "device_id": req.device_id,
        "created_at": time.time()
    })
    print(f"DEBUG: Generated API key: {api_key}")
    return ApiKeyResponse(api_key=api_key)

@app.post("/devices/register", response_model=RegisterDeviceResponse)
async def register_device(req: RegisterDeviceRequest, user_id: str = Depends(require_user)):
    print(f"DEBUG: Received registration request: {req}")
    print(f"DEBUG: User ID: {user_id}")
    
    # Validate public key
    try:
        pub = PublicKey(base64.b64decode(req.public_key_b64))
        print(f"DEBUG: Public key validation successful")
    except Exception as e:
        print(f"DEBUG: Public key validation failed: {e}")
        raise HTTPException(400, f"Invalid public key: {e}")

    # Use the provided device_id instead of generating one
    device_id = req.device_id
    print(f"DEBUG: Using device_id: {device_id}")
    
    # Check if device already exists
    existing_device = await db.devices.find_one({"device_id": device_id})
    if existing_device:
        raise HTTPException(400, f"Device ID {device_id} already exists")
    
    # Insert device
    await db.devices.insert_one({
        "device_id": device_id,
        "user_id": user_id,
        "pubkey_b64": req.public_key_b64,
        "created_at": time.time()
    })
    
    # Update user devices list
    await db.users.update_one(
        {"user_id": user_id},
        {"$addToSet": {"devices": device_id}}
    )
    
    token = issue_device_jwt(user_id, device_id)
    print(f"DEBUG: Successfully registered device {device_id}")
    return RegisterDeviceResponse(device_id=device_id, jwt=token)

@app.post("/stores", response_model=StoreResponse)
async def create_store(req: CreateStoreRequest, user_id: str = Depends(require_user), authorization: str = Header(..., alias="Authorization")):
    # Store DEK is generated server-side (never stored in plaintext on client).
    dek = os.urandom(32)
    store_id = f"s_{secrets.token_hex(8)}"
    
    store_doc = {
        "store_id": store_id,
        "user_id": user_id,
        "name": req.name,
        "dek_b64": base64.b64encode(dek).decode(),
        "wrapped": {},
        "created_at": time.time()
    }
    
    await db.stores.insert_one(store_doc)
    
    # Update user stores list
    await db.users.update_one(
        {"user_id": user_id},
        {"$addToSet": {"stores": store_id}}
    )

    # If caller auth is a device JWT, wrap DEK for that device immediately
    if authorization.lower().startswith("devicejwt "):
        _, token = authorization.split(" ", 1)
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        _, device_id = payload["sub"].split(":")
        await _wrap_for_device(store_id, device_id)

    return StoreResponse(store_id=store_id, name=req.name)

async def _wrap_for_device(store_id: str, device_id: str):
    store = await db.stores.find_one({"store_id": store_id})
    device = await db.devices.find_one({"device_id": device_id})
    
    if not device:
        raise HTTPException(404, "Device not found")
    if device["user_id"] != store["user_id"]:
        raise HTTPException(403, "Device not owned by store owner")
    
    dek = base64.b64decode(store["dek_b64"])
    pubkey = PublicKey(base64.b64decode(device["pubkey_b64"]))
    sealed = SealedBox(pubkey).encrypt(dek, encoder=Base64Encoder)
    wrapped_key = sealed.decode()
    
    # Update store with wrapped key
    await db.stores.update_one(
        {"store_id": store_id},
        {"$set": {f"wrapped.{device_id}": wrapped_key}}
    )

@app.post("/stores/{store_id}/wrap_for_device")
async def add_device_to_store(store_id: str, req: AddDeviceToStoreRequest, user_id: str = Depends(require_user)):
    store = await db.stores.find_one({"store_id": store_id})
    if not store or store["user_id"] != user_id:
        raise HTTPException(404, "Store not found")
    await _wrap_for_device(store_id, req.device_id)
    return {"ok": True}

@app.get("/stores/{store_id}/wrapped_key", response_model=WrappedKeyResponse)
async def get_wrapped_key(store_id: str, user_id: str = Depends(require_user), authorization: str = Header(..., alias="Authorization")):
    # Only device JWT can fetch wrapped key for *itself*
    if not authorization.lower().startswith("devicejwt "):
        raise HTTPException(401, "Use DeviceJWT to fetch device-wrapped key")
    _, token = authorization.split(" ", 1)
    payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    uid, device_id = payload["sub"].split(":")
    if uid != user_id:
        raise HTTPException(403, "User mismatch")

    store = await db.stores.find_one({"store_id": store_id})
    if not store or store["user_id"] != user_id:
        raise HTTPException(404, "Store not found")

    wrapped = store["wrapped"].get(device_id)
    if not wrapped:
        # auto-wrap if device exists
        device = await db.devices.find_one({"device_id": device_id})
        if device:
            await _wrap_for_device(store_id, device_id)
            # Fetch updated store
            store = await db.stores.find_one({"store_id": store_id})
            wrapped = store["wrapped"][device_id]
        else:
            raise HTTPException(404, "No wrapped key for this device")

    return WrappedKeyResponse(store_id=store_id, device_id=device_id, wrapped_dek_b64=wrapped)


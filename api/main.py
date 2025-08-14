import os
import base64
import time
from typing import Dict, List
from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
from nacl.public import PublicKey, SealedBox
from nacl.encoding import Base64Encoder
import jwt
import secrets

# ---- Config (env or defaults) ----
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ISSUER = "mystash"
JWT_EXP_SECONDS = 3600  # 1 hour
# In production: use a real DB (Mongo/Redis/Postgres). This is demo memory storage:
DB = {
    "users": {},         # user_id -> { "email": ..., "devices": [device_id], "stores":[store_id] }
    "devices": {},       # device_id -> { "user_id":..., "name":..., "pubkey_b64":... }
    "stores": {},        # store_id -> { "user_id":..., "name":..., "dek_b64":..., "wrapped": { device_id: wrapped_b64 } }
    "api_keys": {},      # api_key -> user_id  (simple bearer auth for demo)
}

# Bootstrap a demo user + api key:
DEMO_USER_ID = "u_1"
DB["users"][DEMO_USER_ID] = {"email": "demo@example.com", "devices": [], "stores": []}
DB["api_keys"]["demo-api-key"] = DEMO_USER_ID

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
def require_user(authorization: str = Header(..., alias="Authorization")) -> str:
    # Demo supports either "Bearer <api_key>" OR "DeviceJWT <jwt>"
    try:
        scheme, token = authorization.split(" ", 1)
    except ValueError:
        raise HTTPException(401, "Invalid Authorization header")

    if scheme.lower() == "bearer":
        user_id = DB["api_keys"].get(token)
        if not user_id:
            raise HTTPException(401, "Invalid API key")
        return user_id

    if scheme.lower() == "devicejwt":
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], options={"require": ["sub","iss","exp"]})
            if payload.get("iss") != JWT_ISSUER:
                raise HTTPException(401, "Bad issuer")
            # sub = "user_id:device_id"
            sub = payload["sub"]
            user_id, device_id = sub.split(":")
            # basic check device exists
            if device_id not in DB["devices"] or DB["devices"][device_id]["user_id"] != user_id:
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
app = FastAPI(title="MyStash KMS-lite")

@app.post("/apiKey", response_model=ApiKeyResponse)
def get_api_key(req: ApiKeyRequest):
    """Generate an API key for device registration - allows automatic device onboarding."""
    # For demo purposes, we'll associate the device_id with the demo user
    # In production, this might involve additional verification or user association logic
    api_key = f"auto-{secrets.token_hex(16)}"
    DB["api_keys"][api_key] = DEMO_USER_ID
    return ApiKeyResponse(api_key=api_key)

@app.post("/devices/register", response_model=RegisterDeviceResponse)
def register_device(req: RegisterDeviceRequest, user_id: str = Depends(require_user)):
    # Validate public key
    try:
        pub = PublicKey(base64.b64decode(req.public_key_b64), encoder=None)
    except Exception:
        raise HTTPException(400, "Invalid public key")

    # Use the provided device_id instead of generating one
    device_id = req.device_id
    
    # Check if device already exists
    if device_id in DB["devices"]:
        raise HTTPException(400, f"Device ID {device_id} already exists")
    
    DB["devices"][device_id] = {
        "user_id": user_id,
        "device_id": device_id,  # Store the device_id as name
        "pubkey_b64": req.public_key_b64,
    }
    DB["users"][user_id]["devices"].append(device_id)
    token = issue_device_jwt(user_id, device_id)
    return RegisterDeviceResponse(device_id=device_id, jwt=token)

@app.post("/stores", response_model=StoreResponse)
def create_store(req: CreateStoreRequest, user_id: str = Depends(require_user), authorization: str = Header(..., alias="Authorization")):
    # Store DEK is generated server-side (never stored in plaintext on client).
    dek = os.urandom(32)
    store_id = f"s_{secrets.token_hex(8)}"
    DB["stores"][store_id] = {"user_id": user_id, "name": req.name, "dek_b64": base64.b64encode(dek).decode(), "wrapped": {}}
    DB["users"][user_id]["stores"].append(store_id)

    # If caller auth is a device JWT, wrap DEK for that device immediately
    if authorization.lower().startswith("devicejwt "):
        _, token = authorization.split(" ", 1)
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        _, device_id = payload["sub"].split(":")
        _wrap_for_device(store_id, device_id)

    return StoreResponse(store_id=store_id, name=req.name)

def _wrap_for_device(store_id: str, device_id: str):
    store = DB["stores"][store_id]
    device = DB["devices"].get(device_id)
    if not device:
        raise HTTPException(404, "Device not found")
    if device["user_id"] != store["user_id"]:
        raise HTTPException(403, "Device not owned by store owner")
    dek = base64.b64decode(store["dek_b64"])
    pubkey = PublicKey(base64.b64decode(device["pubkey_b64"]))
    sealed = SealedBox(pubkey).encrypt(dek, encoder=Base64Encoder)
    store["wrapped"][device_id] = sealed.decode()

@app.post("/stores/{store_id}/wrap_for_device")
def add_device_to_store(store_id: str, req: AddDeviceToStoreRequest, user_id: str = Depends(require_user)):
    store = DB["stores"].get(store_id)
    if not store or store["user_id"] != user_id:
        raise HTTPException(404, "Store not found")
    _wrap_for_device(store_id, req.device_id)
    return {"ok": True}

@app.get("/stores/{store_id}/wrapped_key", response_model=WrappedKeyResponse)
def get_wrapped_key(store_id: str, user_id: str = Depends(require_user), authorization: str = Header(..., alias="Authorization")):
    # Only device JWT can fetch wrapped key for *itself*
    if not authorization.lower().startswith("devicejwt "):
        raise HTTPException(401, "Use DeviceJWT to fetch device-wrapped key")
    _, token = authorization.split(" ", 1)
    payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    uid, device_id = payload["sub"].split(":")
    if uid != user_id:
        raise HTTPException(403, "User mismatch")

    store = DB["stores"].get(store_id)
    if not store or store["user_id"] != user_id:
        raise HTTPException(404, "Store not found")

    wrapped = store["wrapped"].get(device_id)
    if not wrapped:
        # auto-wrap if device exists
        if device_id in DB["devices"]:
            _wrap_for_device(store_id, device_id)
            wrapped = store["wrapped"][device_id]
        else:
            raise HTTPException(404, "No wrapped key for this device")

    return WrappedKeyResponse(store_id=store_id, device_id=device_id, wrapped_dek_b64=wrapped)


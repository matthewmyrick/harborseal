# cli.py
import os, json, base64, getpass, pathlib, requests, secrets
import typer
from typing import Optional
from nacl.public import PrivateKey, PublicKey, SealedBox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = typer.Typer(help="HarborSeal CLI")

HOME = pathlib.Path.home()
CONF_DIR = HOME / ".config" / "harborseal"
CONF_DIR.mkdir(parents=True, exist_ok=True)

def _read(path): return path.read_bytes()
def _write(path, data: bytes, mode=0o600):
    path.write_bytes(data)
    os.chmod(path, mode)

def save_json(path, obj):
    _write(path, json.dumps(obj, indent=2).encode())

def load_json(path, default=None):
    if not path.exists(): return default
    return json.loads(path.read_text())

def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, aad)
    return nonce + ct

def aead_decrypt(key: bytes, data: bytes, aad: bytes = b"") -> bytes:
    aes = AESGCM(key)
    nonce, ct = data[:12], data[12:]
    return aes.decrypt(nonce, ct, aad)

def get_cfg():
    return load_json(CONF_DIR / "config.json", default={"server_url": "https://api.harborseal.com", "device": {}, "stores": {}})

def save_cfg(cfg): save_json(CONF_DIR / "config.json", cfg)

def generate_device_id():
    return secrets.token_hex(16)

def get_device_paths(device_id: str):
    priv = CONF_DIR / f"{device_id}.key"
    return priv

def generate_device_keypair():
    sk = PrivateKey.generate()
    pk = sk.public_key
    return sk, pk

def load_private_key(device_id: str) -> PrivateKey:
    p = get_device_paths(device_id)
    if not p.exists():
        raise typer.Exit(f"Device key not found: {p}")
    return PrivateKey(_read(p))

def b64(b: bytes) -> str: return base64.b64encode(b).decode()
def b64dec(s: str) -> bytes: return base64.b64decode(s)

@app.command()
def init():
    """Initialize device with interactive setup and create local secret store."""
    cfg = get_cfg()
    
    # Check if already initialized
    if cfg.get("device"):
        typer.echo("Device already initialized. To reinitialize, please delete ~/.config/harborseal/config.json")
        raise typer.Exit(1)
    
    # Interactive prompts
    typer.echo("Welcome to HarborSeal CLI Setup!\n")
    
    # Get secret store name first
    store_name = typer.prompt("Secret store name")
    
    # Auto-generate device ID
    device_id = generate_device_id()
    server_url = cfg["server_url"]  # Use default from config
    
    typer.echo(f"Device ID: {device_id}")
    typer.echo(f"Server URL: {server_url}")

    # Generate device keypair
    sk, pk = generate_device_keypair()
    priv_path = get_device_paths(device_id)
    if priv_path.exists():
        typer.echo(f"Device key already exists at {priv_path}")
        raise typer.Exit(1)
    _write(priv_path, bytes(sk))
    typer.echo(f"✓ Generated device keypair")

    # Register device using apiKey route (background registration)
    try:
        # First try to get an API key from the apiKey endpoint
        r = requests.post(f"{server_url}/apiKey", json={
            "device_id": device_id
        }, timeout=10)
        r.raise_for_status()
        api_response = r.json()
        api_key = api_response.get("api_key")
        
        if not api_key:
            typer.echo("Failed to obtain API key from server")
            raise typer.Exit(1)
            
        # Now register the device with the obtained API key
        headers = {"Authorization": f"Bearer {api_key}"}
        r = requests.post(f"{server_url}/devices/register", json={
            "device_id": device_id,
            "public_key_b64": b64(bytes(pk))
        }, headers=headers, timeout=10)
        r.raise_for_status()
        resp = r.json()
        registered_device_id = resp["device_id"]
        device_jwt = resp["jwt"]
        
    except Exception as e:
        typer.echo(f"Failed to register device: {e}")
        # Clean up private key
        if priv_path.exists():
            priv_path.unlink()
        raise typer.Exit(1)

    cfg["device"] = {"device_id": device_id, "jwt": device_jwt}
    save_cfg(cfg)
    typer.echo(f"✓ Registered device {device_id}")
    
    # Automatically create the local secret store
    typer.echo(f"\nCreating local secret store '{store_name}'...")
    try:
        headers = {"Authorization": f"DeviceJWT {device_jwt}"}
        r = requests.post(f"{server_url}/stores", json={"name": store_name}, headers=headers, timeout=10)
        r.raise_for_status()
        store = r.json()
        cfg["stores"][store["name"]] = {"id": store["store_id"], "file": str(CONF_DIR / f"{store['name']}.json.enc")}
        save_cfg(cfg)
        typer.echo(f"✓ Created secret store '{store['name']}'")
        
        # Fetch and cache the DEK
        r = requests.get(f"{server_url}/stores/{store['store_id']}/wrapped_key", headers=headers, timeout=10)
        r.raise_for_status()
        wrapped_b64 = r.json()["wrapped_dek_b64"]
        
        # Unwrap and cache DEK
        sealed = SealedBox(sk)
        dek = sealed.decrypt(b64dec(wrapped_b64))
        
        # Create filekey if doesn't exist
        filekey_path = CONF_DIR / "filekey.bin"
        if not filekey_path.exists():
            _write(filekey_path, os.urandom(32))
        filekey = _read(filekey_path)
        
        # Cache the DEK
        dek_cache_path = CONF_DIR / f"{store_name}.dek"
        blob = aead_encrypt(filekey, dek)
        _write(dek_cache_path, blob)
        
        # Initialize empty store file
        empty_store = {}
        store_blob = aead_encrypt(dek, json.dumps(empty_store, indent=2).encode())
        store_file_path = CONF_DIR / f"{store_name}.json.enc"
        _write(store_file_path, store_blob)
        
        typer.echo(f"✓ Local secret store ready at {store_file_path}")
        typer.echo(f"\n✅ Setup complete! You can now use commands like:")
        typer.echo(f"  harborseal set --store {store_name} --key MY_SECRET --value my_value")
        typer.echo(f"  harborseal get --store {store_name} --key MY_SECRET")
        typer.echo(f"  harborseal list --store {store_name}")
        
    except Exception as e:
        typer.echo(f"Warning: Could not create store automatically: {e}")
        typer.echo(f"You can create it manually with: harborseal create-store --name {store_name}")

@app.command()
def config(url: Optional[str] = typer.Option(None, help="Set new server URL")):
    """View or update configuration settings."""
    cfg = get_cfg()
    
    if url:
        # Update server URL
        cfg["server_url"] = url
        save_cfg(cfg)
        typer.echo(f"✓ Updated server URL to: {url}")
    else:
        # Display current config
        typer.echo("Current configuration:")
        typer.echo(f"  Server URL: {cfg['server_url']}")
        if cfg.get("device"):
            typer.echo(f"  Device ID: {cfg['device']['device_id']}")
        else:
            typer.echo("  Device: Not initialized")
        
        store_count = len(cfg.get("stores", {}))
        typer.echo(f"  Secret stores: {store_count}")
        if store_count > 0:
            for store_name in cfg["stores"].keys():
                typer.echo(f"    - {store_name}")

@app.command()
def create_store(name: str = typer.Option(...),):
    """Create a store on server and wrap its DEK for this device."""
    cfg = get_cfg()
    server = cfg["server_url"]; dev = cfg.get("device") or {}
    if not (server and dev):
        raise typer.Exit("Run `init` first.")

    headers = {"Authorization": f"DeviceJWT {dev['jwt']}"}
    r = requests.post(f"{server}/stores", json={"name": name}, headers=headers, timeout=10)
    r.raise_for_status()
    store = r.json()  # {store_id, name}
    cfg["stores"][store["name"]] = {"id": store["store_id"], "file": str(CONF_DIR / f"{store['name']}.json.enc")}
    save_cfg(cfg)
    typer.echo(f"Created store {store['name']} ({store['store_id']}).")

@app.command()
def pull_key(store: str = typer.Option(..., help="Store name")):
    """Fetch wrapped DEK for this device and cache it locally (encrypted under device key)."""
    cfg = get_cfg()
    server = cfg["server_url"]; dev = cfg.get("device")
    info = cfg["stores"].get(store)
    if not info: raise typer.Exit("Unknown store. Create or add it first.")
    store_id = info["id"]

    # Fetch wrapped DEK
    headers = {"Authorization": f"DeviceJWT {dev['jwt']}"}
    r = requests.get(f"{server}/stores/{store_id}/wrapped_key", headers=headers, timeout=10)
    r.raise_for_status()
    wrapped_b64 = r.json()["wrapped_dek_b64"]

    # Unwrap locally with private key
    sk = load_private_key(cfg["device"]["device_id"])
    sealed = SealedBox(sk)
    dek = sealed.decrypt(b64dec(wrapped_b64))  # 32 bytes

    # Cache DEK: encrypt under device private key-derived box? Simpler: store in memory only.
    # For demo, store DEK encrypted with a machine-local key file:
    dek_cache_path = CONF_DIR / f"{store}.dek"
    # Derive a file key (random) once:
    filekey_path = CONF_DIR / "filekey.bin"
    if not filekey_path.exists():
        _write(filekey_path, os.urandom(32))
    filekey = _read(filekey_path)
    blob = aead_encrypt(filekey, dek)
    _write(dek_cache_path, blob)
    typer.echo(f"Cached DEK at {dek_cache_path} (sealed).")

def _load_dek(store: str) -> bytes:
    # In a real design, you would prefer OS keychain / TPM / age key; here: AES-GCM sealed cache.
    filekey = _read(CONF_DIR / "filekey.bin")
    blob = _read(CONF_DIR / f"{store}.dek")
    return aead_decrypt(filekey, blob)

def _store_path(store: str) -> pathlib.Path:
    cfg = get_cfg()
    info = cfg["stores"].get(store)
    if not info: raise typer.Exit("Unknown store")
    return pathlib.Path(info["file"])

def _read_store(store: str) -> dict:
    path = _store_path(store)
    if not path.exists(): return {}
    dek = _load_dek(store)
    plaintext = aead_decrypt(dek, _read(path))
    return json.loads(plaintext)

def _write_store(store: str, data: dict):
    path = _store_path(store)
    dek = _load_dek(store)
    blob = aead_encrypt(dek, json.dumps(data, indent=2).encode())
    _write(path, blob)

@app.command()
def set(store: str = typer.Option(...), key: str = typer.Option(...), value: str = typer.Option(...)):
    """Set a secret key=value in the local encrypted store file."""
    data = _read_store(store)
    data[key] = value
    _write_store(store, data)
    typer.echo(f"Set {key} in {store}.")

@app.command()
def get(store: str = typer.Option(...), key: str = typer.Option(...), export: bool = typer.Option(False, help="Print as KEY=VALUE")):
    """Get a secret value; optionally print as KEY=VALUE for shell export."""
    data = _read_store(store)
    if key not in data: raise typer.Exit("Key not found")
    if export:
        print(f"{key}={data[key]}")
    else:
        print(data[key])

@app.command()
def list(store: str = typer.Option(...)):
    """List keys in the store (names only)."""
    data = _read_store(store)
    for k in sorted(data.keys()):
        print(k)

if __name__ == "__main__":
    app()


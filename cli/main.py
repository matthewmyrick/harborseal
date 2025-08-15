# cli.py
import os, json, base64, getpass, pathlib, requests, secrets
import typer
from typing import Optional, List
from nacl.public import PrivateKey, PublicKey, SealedBox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fuzzywuzzy import fuzz, process

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
    return load_json(CONF_DIR / "config.json", default={"server_url": "", "device": {}, "stores": {}})

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
    
    # Check if server URL is configured
    server_url = cfg["server_url"]
    if not server_url:
        typer.echo("❌ Server URL is not configured.")
        typer.echo("Please set the server URL first using:")
        typer.echo("  harborseal config --url <your-server-url>")
        typer.echo("\nExample:")
        typer.echo("  harborseal config --url https://api.harborseal.com")
        raise typer.Exit(1)
    
    # Auto-generate device ID
    device_id = generate_device_id()
    
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
        
        # Initialize empty store file (no DEK caching)
        empty_store = {}
        store_file_path = CONF_DIR / f"{store_name}.json.enc"
        # Create empty encrypted file - will be populated when first used
        _write(store_file_path, b"")
        
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
def refresh(store: Optional[str] = typer.Option(None, help="Store name to test access")):
    """Test JWT validity and server connectivity."""
    cfg = get_cfg()
    if not cfg.get("device"):
        typer.echo("❌ Device not initialized. Run 'harborseal init' first.")
        return
    
    if store:
        try:
            # Test by attempting to load DEK
            _load_dek(store)
            typer.echo(f"✅ Successfully connected to store '{store}'")
        except SystemExit:
            typer.echo(f"❌ Failed to access store '{store}' - JWT may be expired")
    else:
        # Test basic JWT validity
        try:
            import jwt as jwt_lib
            device_jwt = cfg["device"]["jwt"]
            # Decode without verification to check expiration
            payload = jwt_lib.decode(device_jwt, options={"verify_signature": False})
            import time
            exp_time = payload.get("exp", 0)
            current_time = int(time.time())
            
            if exp_time > current_time:
                remaining = exp_time - current_time
                typer.echo(f"✅ JWT valid for {remaining // 60} more minutes")
            else:
                typer.echo("❌ JWT expired. Run 'harborseal init' to re-authenticate.")
        except Exception as e:
            typer.echo(f"❌ JWT validation failed: {e}")

def _load_dek(store: str) -> bytes:
    """Fetch DEK from server using JWT - no local caching for security."""
    cfg = get_cfg()
    server_url = cfg["server_url"]
    device = cfg.get("device")
    
    if not device or not device.get("jwt"):
        raise typer.Exit("Device not initialized. Run 'harborseal init' first.")
    
    store_info = cfg["stores"].get(store)
    if not store_info:
        raise typer.Exit(f"Unknown store '{store}'. Available stores: {list(cfg['stores'].keys())}")
    
    store_id = store_info["id"]
    device_id = device["device_id"]
    
    # Fetch wrapped DEK from server using JWT
    try:
        headers = {"Authorization": f"DeviceJWT {device['jwt']}"}
        r = requests.get(f"{server_url}/stores/{store_id}/wrapped_key", headers=headers, timeout=10)
        r.raise_for_status()
        wrapped_b64 = r.json()["wrapped_dek_b64"]
        
        # Unwrap DEK using device private key
        sk = load_private_key(device_id)
        sealed = SealedBox(sk)
        dek = sealed.decrypt(b64dec(wrapped_b64))
        
        return dek
        
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            # JWT expired - need to re-authenticate
            typer.echo("Authentication expired. Please run 'harborseal init' to re-authenticate.")
            raise typer.Exit(1)
        else:
            typer.echo(f"Failed to fetch encryption key: {e}")
            raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"Failed to decrypt store key: {e}")
        raise typer.Exit(1)

def _store_path(store: str) -> pathlib.Path:
    cfg = get_cfg()
    info = cfg["stores"].get(store)
    if not info: raise typer.Exit("Unknown store")
    return pathlib.Path(info["file"])

def _read_store(store: str) -> dict:
    path = _store_path(store)
    if not path.exists():
        return {}
    
    # Check if file is empty (newly created)
    if path.stat().st_size == 0:
        return {}
    
    dek = _load_dek(store)
    try:
        plaintext = aead_decrypt(dek, _read(path))
        return json.loads(plaintext)
    except Exception:
        # If decryption fails, might be empty file or corrupted - start fresh
        return {}

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

@app.command()
def find(store: str = typer.Option(...), query: str = typer.Option(...), limit: int = typer.Option(10, help="Max results to show")):
    """Fuzzy search for keys in the store."""
    data = _read_store(store)
    if not data:
        typer.echo("Store is empty")
        return
    
    # Get all keys
    all_keys = list(data.keys())
    
    # Perform fuzzy search
    matches = process.extract(query, all_keys, limit=limit, scorer=fuzz.partial_ratio)
    
    if not matches:
        typer.echo(f"No matches found for '{query}'")
        return
    
    typer.echo(f"Found {len(matches)} matches for '{query}':")
    for key, score in matches:
        typer.echo(f"  {score:3d}% - {key}")

@app.command()
def search(store: str = typer.Option(...), query: str = typer.Option(...), interactive: bool = typer.Option(False, help="Interactive selection")):
    """Search and optionally get a key value interactively."""
    data = _read_store(store)
    if not data:
        typer.echo("Store is empty")
        return
    
    # Get all keys
    all_keys = list(data.keys())
    
    # Perform fuzzy search
    matches = process.extract(query, all_keys, limit=20, scorer=fuzz.partial_ratio)
    
    if not matches:
        typer.echo(f"No matches found for '{query}'")
        return
    
    if not interactive:
        # Just show the results
        typer.echo(f"Found {len(matches)} matches for '{query}':")
        for key, score in matches:
            typer.echo(f"  {score:3d}% - {key}")
        return
    
    # Interactive mode - let user select
    typer.echo(f"Found {len(matches)} matches for '{query}':")
    for i, (key, score) in enumerate(matches):
        typer.echo(f"  {i+1:2d}. {score:3d}% - {key}")
    
    while True:
        try:
            choice = typer.prompt("\nSelect a key (number), or 'q' to quit")
            if choice.lower() == 'q':
                return
            
            idx = int(choice) - 1
            if 0 <= idx < len(matches):
                selected_key = matches[idx][0]
                value = data[selected_key]
                
                # Ask what to do with the value
                action = typer.prompt(f"Key: {selected_key}\nActions: (v)iew, (c)opy to clipboard, (e)xport format", default="v")
                
                if action.lower() == 'v':
                    typer.echo(f"\nValue: {value}")
                elif action.lower() == 'c':
                    try:
                        import subprocess
                        subprocess.run(['pbcopy'], input=value.encode(), check=True)
                        typer.echo("✓ Copied to clipboard")
                    except Exception as e:
                        typer.echo(f"Failed to copy to clipboard: {e}")
                        typer.echo(f"Value: {value}")
                elif action.lower() == 'e':
                    typer.echo(f"{selected_key}={value}")
                else:
                    typer.echo(f"Value: {value}")
                
                if typer.confirm("\nSearch again?", default=False):
                    continue
                else:
                    break
            else:
                typer.echo("Invalid selection")
        except ValueError:
            typer.echo("Please enter a valid number or 'q' to quit")
        except KeyboardInterrupt:
            typer.echo("\nExiting...")
            break

if __name__ == "__main__":
    app()


"""RaspISE configuration loader."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


# ---------------------------------------------------------------------------
# Pydantic models — every section of config.yaml has a typed model
# ---------------------------------------------------------------------------

class RadiusClientConfig(BaseModel):
    name: str
    address: str
    secret: str


class RadiusConfig(BaseModel):
    enabled: bool = True
    host: str = "0.0.0.0"
    auth_port: int = 1812
    acct_port: int = 1813
    clients: list[RadiusClientConfig] = []
    default_vlan: int = 10
    guest_vlan: int = 20
    reject_vlan: int = 99


class TacacsClientConfig(BaseModel):
    address: str
    key: str


class TacacsConfig(BaseModel):
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 49
    key: str = "tacacs_secret"
    clients: list[TacacsClientConfig] = []


class WebConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    admin_username: str = "admin"
    admin_password: str = "RaspISE@admin1"


class ApiConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8081
    token_expire_minutes: int = 60


class PortalConfig(BaseModel):
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 8082
    redirect_url: str = "http://localhost:8082"
    session_hours: int = 8
    guest_ssid: str = "RaspISE-Guest"
    guest_psk: str = "guest_password"


class ProfilerConfig(BaseModel):
    enabled: bool = True
    listen_interface: str = "eth0"
    oui_db: str = "/var/lib/raspise/oui.csv"


class DisplayConfig(BaseModel):
    enabled: bool = True
    driver: str = "simulation"   # ili9341 | st7789 | simulation
    spi_port: int = 0
    spi_device: int = 0
    dc_pin: int = 24
    rst_pin: int = 25
    backlight_pin: int = 18
    rotation: int = 0
    brightness: int = 100
    screen_cycle_seconds: int = 5
    screens: list[str] = ["auth_log", "stats", "sessions", "network", "qr_code"]


class ServerConfig(BaseModel):
    name: str = "RaspISE-01"
    secret_key: str = "change_me"
    debug: bool = False
    log_level: str = "INFO"
    log_file: str = "/var/log/raspise/raspise.log"


class LogSyslogConfig(BaseModel):
    enabled: bool = False
    address: str = "/dev/log"     # path for local Unix socket OR "host:port" for remote
    facility: str = "local0"      # local0–local7, daemon, auth, syslog …
    protocol: str = "udp"         # udp | tcp  (only used when address is host:port)
    port: int = 514


class LogWebhookConfig(BaseModel):
    enabled: bool = False
    url: str = ""                  # HTTPS endpoint to POST JSON log records to
    level: str = "WARNING"         # only forward this level and above
    timeout_seconds: float = 3.0
    headers: dict[str, str] = {}   # e.g. {"Authorization": "Bearer token"}
    batch_size: int = 10           # queue this many records, then flush in one request
    batch_interval_seconds: float = 5.0


class LogGraylogConfig(BaseModel):
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 12201             # standard GELF UDP port
    protocol: str = "udp"         # udp | tcp


class LogForwardingConfig(BaseModel):
    syslog: LogSyslogConfig = Field(default_factory=LogSyslogConfig)
    webhook: LogWebhookConfig = Field(default_factory=LogWebhookConfig)
    graylog: LogGraylogConfig = Field(default_factory=LogGraylogConfig)


class LdapConfig(BaseModel):
    enabled: bool = False
    server: str = "ldap://dc.example.com"
    port: int = 389
    use_ssl: bool = False
    bind_dn: str = ""                  # e.g. "CN=svc-raspise,OU=Service Accounts,DC=example,DC=com"
    bind_password: str = ""
    base_dn: str = ""                  # e.g. "DC=example,DC=com"
    user_filter: str = "(sAMAccountName={username})"
    group_attribute: str = "memberOf"  # AD group membership attribute
    group_map: dict[str, str] = {}     # LDAP group DN → RaspISE group name


class DatabaseConfig(BaseModel):
    url: str = "sqlite+aiosqlite:////var/lib/raspise/raspise.db"


class AppConfig(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    radius: RadiusConfig = Field(default_factory=RadiusConfig)
    tacacs: TacacsConfig = Field(default_factory=TacacsConfig)
    web: WebConfig = Field(default_factory=WebConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
    portal: PortalConfig = Field(default_factory=PortalConfig)
    profiler: ProfilerConfig = Field(default_factory=ProfilerConfig)
    display: DisplayConfig = Field(default_factory=DisplayConfig)
    log_forwarding: LogForwardingConfig = Field(default_factory=LogForwardingConfig)
    ldap: LdapConfig = Field(default_factory=LdapConfig)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

_DEFAULT_PATHS = [
    Path("config.yaml"),
    Path("raspise/config/config.yaml"),
    Path("/etc/raspise/config.yaml"),
]


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open() as f:
        return yaml.safe_load(f) or {}


@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    """Load config from the first found YAML file, then env overrides."""
    # Allow explicit path via env variable
    env_path = os.environ.get("RASPISE_CONFIG")
    data: dict[str, Any] = {}

    if env_path:
        data = _load_yaml(Path(env_path))
    else:
        for p in _DEFAULT_PATHS:
            if p.exists():
                data = _load_yaml(p)
                break

    return AppConfig.model_validate(data)

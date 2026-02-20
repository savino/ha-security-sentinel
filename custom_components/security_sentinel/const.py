"""Constants for Security Sentinel integration."""

DOMAIN = "security_sentinel"
VERSION = "0.1.0"

# Config keys
CONF_SCAN_INTERVAL = "scan_interval"
CONF_FAILED_LOGIN_THRESHOLD = "failed_login_threshold"
CONF_BRUTE_FORCE_WINDOW = "brute_force_window"
CONF_NOTIFY_SERVICE = "notify_service"
CONF_EMAIL_RECIPIENT = "email_recipient"
CONF_SMTP_HOST = "smtp_host"
CONF_SMTP_PORT = "smtp_port"
CONF_SMTP_USERNAME = "smtp_username"
CONF_SMTP_PASSWORD = "smtp_password"
CONF_GEO_API_KEY = "geo_api_key"

# Defaults
DEFAULT_SCAN_INTERVAL = 60
DEFAULT_FAILED_LOGIN_THRESHOLD = 5
DEFAULT_BRUTE_FORCE_WINDOW = 60
DEFAULT_NOTIFY_SERVICE = "persistent_notification"
DEFAULT_SMTP_PORT = 587

# Event types
EVENT_AUTH_FAILED = "AUTH_FAILED"
EVENT_BRUTE_FORCE = "BRUTE_FORCE"
EVENT_NEW_DEVICE = "NEW_DEVICE"
EVENT_SUSPICIOUS_SERVICE = "SUSPICIOUS_SERVICE"
EVENT_EXTERNAL_ACCESS = "EXTERNAL_ACCESS"

# Severity levels
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

SEVERITY_SCORES = {
    SEVERITY_LOW: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_HIGH: 5,
    SEVERITY_CRITICAL: 10,
}

THREAT_THRESHOLDS = [
    (20, SEVERITY_CRITICAL),
    (10, SEVERITY_HIGH),
    (4, SEVERITY_MEDIUM),
    (0, SEVERITY_LOW),
]

# HA bus event name
HA_EVENT_NAME = "security_sentinel_event"

# Storage
STORAGE_KEY = f"{DOMAIN}.events"
STORAGE_VERSION = 1

# Sensor keys
SENSOR_FAILED_LOGINS = "failed_logins"
SENSOR_LAST_EVENT = "last_event"
SENSOR_THREAT_LEVEL = "threat_level"

# Suspicious services to monitor
SUSPICIOUS_SERVICES = [
    "shell_command",
    "python_script",
    "homeassistant.restart",
    "homeassistant.stop",
]

# Private/local IP prefixes
PRIVATE_IP_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "::1", "fe80:",
)

import os
import configparser
from pathlib import Path


DEFAULT_CONFIG = Path(__file__).parent.resolve() / "default.cfg"
DEFAULT_WELCOME_FILES = Path(__file__).parent.resolve() / "templates/_welcome"
OPENCVE_HOME = os.environ.get("OPENCVE_HOME") or str(Path.home() / "opencve")
OPENCVE_CONFIG = os.environ.get("OPENCVE_CONFIG") or str(
    Path(OPENCVE_HOME) / "opencve.cfg"
)
OPENCVE_WELCOME_FILES = os.environ.get("OPENCVE_WELCOME_FILES") or str(
    Path(OPENCVE_HOME) / "welcome_html"
)

# Load the configuration
config = configparser.ConfigParser()

if Path(OPENCVE_CONFIG).exists():
    config.read(OPENCVE_CONFIG)
else:
    config.read(DEFAULT_CONFIG)

    # Generate a secret to avoid the following warning when init the config :
    # WARNING: Flask-User TokenManager: SECRET_KEY is shorter than 32 bytes.
    config.set("core", "secret_key", " " * 32)

import os

from opencve import create_app
from opencve.extensions import cel


env = os.environ.get("OPENCVE_ENV", "production")
app = create_app(env)

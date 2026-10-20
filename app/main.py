"""Production ASGI entrypoint. GPU loading happens only during lifespan."""
from app.enterprise.application import create_app

app = create_app()

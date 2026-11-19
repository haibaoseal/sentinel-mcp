"""Deployed ASGI entry point.

Kept separate from `main.py` so importing the factory in tests never opens a
database or reads the developer's `.env` as a side effect of import.
"""

from app.api.main import create_app

app = create_app()

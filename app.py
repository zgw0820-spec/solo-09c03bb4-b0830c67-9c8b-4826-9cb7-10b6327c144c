"""Conventional project-root WSGI entry point.

Allows both ``flask --app app run`` and ``gunicorn app:app`` in addition to
``wsgi:app`` / ``pcapdiff.app:create_app``.
"""

import os

from pcapdiff.app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")),
            debug=False)

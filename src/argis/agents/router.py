"""Router wrapper that preserves engine protocol boundaries."""

from __future__ import annotations

from engine.config import RouterConfig
from engine.router import plan_routes
from schemas.email_schema import EmailInput


def route_email(email: EmailInput, config: RouterConfig | None = None):
    return plan_routes(email, config or RouterConfig())

"""Recoverable port management for v2ray-agent.

The command line entry point owns the shared writer lock. Backend users must
hold the same lock when changing configuration, policies, or kernel objects.
"""

__version__ = "1.0.0"

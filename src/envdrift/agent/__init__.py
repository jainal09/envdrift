"""Agent communication and project registry module.

This module handles communication between the envdrift CLI and the background
agent daemon. It manages the projects.json registry that tracks which projects
the agent should watch.
"""

from envdrift.agent.registry import (
    ProjectEntry,
    ProjectRegistry,
    get_registry,
    list_projects,
    register_project,
    unregister_project,
)

__all__ = [
    "ProjectEntry",
    "ProjectRegistry",
    "get_registry",
    "register_project",
    "unregister_project",
    "list_projects",
]

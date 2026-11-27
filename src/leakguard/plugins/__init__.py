from .apis import API_PLUGINS
from .base import Context, Plugin, SkipSource
from .tools import TOOL_PLUGINS

ALL_PLUGINS: list[Plugin] = [*API_PLUGINS, *TOOL_PLUGINS]
BY_NAME = {p.name: p for p in ALL_PLUGINS}


def reload_custom() -> list:
    """(Re)load the tools defined in JSON (custom_tools.py): your own and the lab's example."""
    from .. import wording
    from .manifest import ManifestTool, load_all
    ALL_PLUGINS[:] = [p for p in ALL_PLUGINS if not isinstance(p, ManifestTool)]
    BY_NAME.clear()
    custom = load_all()
    ALL_PLUGINS.extend(custom)
    BY_NAME.update({p.name: p for p in ALL_PLUGINS})
    for p in custom:                                   # progress and reports show the tool's own name
        wording.SOURCE.setdefault(p.name, p.m["name"])
    return custom


def active(settings) -> list[Plugin]:
    """The plugins that take part in this profile's checks."""
    return [p for p in ALL_PLUGINS if getattr(p, "available", lambda s: True)(settings)]


reload_custom()

__all__ = ["ALL_PLUGINS", "BY_NAME", "Context", "Plugin", "SkipSource", "active", "reload_custom"]

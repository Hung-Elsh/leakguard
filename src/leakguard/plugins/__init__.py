from .apis import API_PLUGINS
from .base import Context, Plugin, SkipSource
from .tools import TOOL_PLUGINS

ALL_PLUGINS: list[Plugin] = [*API_PLUGINS, *TOOL_PLUGINS]
BY_NAME = {p.name: p for p in ALL_PLUGINS}

__all__ = ["ALL_PLUGINS", "BY_NAME", "Context", "Plugin", "SkipSource"]

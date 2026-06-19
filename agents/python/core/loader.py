import os
import importlib
import logging

log = logging.getLogger("phantom.core.loader")


class ModuleLoader:
    """Discovers and loads agent modules."""

    def __init__(self, dispatcher):
        self.dispatcher = dispatcher
        self._loaded: dict[str, object] = {}

    def discover_modules(self, modules_dir: str) -> list[str]:
        """Find all loadable .py modules in directory."""
        found = []
        if not os.path.isdir(modules_dir):
            log.warning(f"Modules directory not found: {modules_dir}")
            return found
        for f in os.listdir(modules_dir):
            if f.endswith(".py") and not f.startswith("_"):
                found.append(f[:-3])
        log.debug(f"Discovered modules: {found}")
        return found

    def load_module(self, name: str, package: str = "modules") -> bool:
        """Import a module and register its commands with the dispatcher."""
        if name in self._loaded:
            return True
        try:
            mod = importlib.import_module(f".{name}", package=package)
            if not hasattr(mod, "COMMANDS"):
                log.warning(f"Module '{name}' has no COMMANDS dict, skipping")
                return False
            count = self.dispatcher.register_module(mod)
            self._loaded[name] = mod
            log.info(f"Loaded module '{name}' ({count} commands)")
            return True
        except Exception as e:
            log.error(f"Failed to load module '{name}': {e}")
            return False

    def load_all(self, modules_dir: str, package: str = "modules") -> int:
        """Load all discovered modules. Returns count of successfully loaded."""
        loaded = 0
        for name in self.discover_modules(modules_dir):
            if self.load_module(name, package):
                loaded += 1
        return loaded

    @property
    def loaded_modules(self) -> list[str]:
        return list(self._loaded.keys())

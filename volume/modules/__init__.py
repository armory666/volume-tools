import importlib
import inspect
import pkgutil
import sys

from volume.core import catalog
from volume.core.module_base import BaseModule


def _warn(message):
    print(f"[!] {message}", file=sys.stderr)


def load_all_modules():
    found = {}
    for _loader, module_name, _is_pkg in pkgutil.walk_packages(__path__, __name__ + "."):
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:
            _warn(f"Failed to load {module_name}: {exc}")
            continue
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BaseModule)
                and obj is not BaseModule
                and getattr(obj, "__module__", "") == module.__name__
            ):
                try:
                    instance = obj()
                except Exception as exc:
                    _warn(f"Failed to instantiate {module_name}.{obj.__name__}: {exc}")
                    continue
                if instance.id in found:
                    _warn(f"Duplicate module id '{instance.id}' in {module_name}")
                    continue
                found[instance.id] = instance

    ordered = sorted(found.values(), key=catalog.sort_key)
    return {module.id: module for module in ordered}

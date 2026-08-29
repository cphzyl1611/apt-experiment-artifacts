#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest


PACKAGE_ROOT = Path(__file__).resolve().parent
SOURCE_ROOT = PACKAGE_ROOT.parent


def main() -> int:
    sys.dont_write_bytecode = True
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    sys.path.insert(0, str(PACKAGE_ROOT))
    sys.path.insert(1, str(PACKAGE_ROOT / "09_tests"))
    with tempfile.TemporaryDirectory(prefix="a2-r5-packaged-tests-") as td:
        view = Path(td) / "source"
        view.mkdir()
        for source in SOURCE_ROOT.iterdir():
            if source.name in {PACKAGE_ROOT.name, "tools", "tests"}:
                continue
            os.symlink(source, view / source.name, target_is_directory=source.is_dir())
        os.symlink(PACKAGE_ROOT / "tools", view / "tools", target_is_directory=True)
        os.symlink(PACKAGE_ROOT / "tests", view / "tests", target_is_directory=True)
        suite = unittest.TestSuite()
        loader = unittest.defaultTestLoader
        for path in sorted((PACKAGE_ROOT / "09_tests").glob("test_*.py")):
            name = f"r5_packaged_{path.stem}"
            spec = importlib.util.spec_from_file_location(name, path)
            if spec is None or spec.loader is None:
                raise RuntimeError(f"cannot load packaged test: {path.name}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
            if hasattr(module, "ROOT"):
                module.ROOT = view
            if hasattr(module, "R4_PACKAGE"):
                module.R4_PACKAGE = view / "FA1B2de_Current86_BSO_A2_P0_P1_Execution_Contract_R4"
            suite.addTests(loader.loadTestsFromModule(module))
        for name, module in tuple(sys.modules.items()):
            if name.endswith("test_r5_contract_fixes"):
                if hasattr(module, "ROOT"):
                    module.ROOT = view
                if hasattr(module, "R4_PACKAGE"):
                    module.R4_PACKAGE = view / "FA1B2de_Current86_BSO_A2_P0_P1_Execution_Contract_R4"
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())

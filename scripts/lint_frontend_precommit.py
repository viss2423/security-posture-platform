"""Pre-commit: run ESLint on staged frontend files. Works on Windows and Unix."""

import os
import subprocess
import sys


def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    frontend_dir = os.path.join(repo_root, "services", "frontend")
    prefix = os.path.join("services", "frontend") + os.sep
    prefix_alt = "services/frontend/"
    rel_files = []
    for f in sys.argv[1:]:
        path = f.replace("/", os.sep)
        if path.startswith(prefix) or f.startswith(prefix_alt):
            rel = path[len(prefix) :] if path.startswith(prefix) else f[len(prefix_alt) :]
            rel_files.append(rel.replace("\\", "/"))
    if not rel_files:
        return 0
    result = subprocess.run(
        ["npx", "eslint", "--max-warnings", "0"] + rel_files,
        cwd=frontend_dir,
        shell=(os.name == "nt"),
    )
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())

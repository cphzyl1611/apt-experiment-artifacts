#!/usr/bin/env python3
from a2_role_runtime import main


if __name__ == "__main__":
    raise SystemExit(main(["--role", "PRIMARY", *__import__("sys").argv[1:]]))

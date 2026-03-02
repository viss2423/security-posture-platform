#!/usr/bin/env python3
"""
Small helper to call OpenAI Codex-style completions from the repository.

Usage:
  python scripts/codex_client.py --prompt "Write a function to reverse a string"
  echo "def foo():" | python scripts/codex_client.py

Environment:
  OPENAI_API_KEY  - required (your OpenAI API key)
  OPENAI_MODEL    - optional (defaults to code-davinci-002)
"""

from __future__ import annotations

import argparse
import os
import sys

try:
    import openai
except Exception:
    print(
        "Missing dependency 'openai'. Install with: pip install -r tools/codex_integration/requirements.txt",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    from dotenv import load_dotenv
except Exception:
    # dotenv is optional; requirements.txt includes python-dotenv. If missing, we'll continue.
    load_dotenv = None


def call_codex(prompt: str, model: str, max_tokens: int = 256, temperature: float = 0.2) -> str:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set. Export it or add to your environment.")
    openai.api_key = api_key

    # Use Completion.create for Codex-style models
    resp = openai.Completion.create(
        engine=model,
        prompt=prompt,
        max_tokens=max_tokens,
        temperature=temperature,
        n=1,
    )
    return resp.choices[0].text


def main() -> None:
    parser = argparse.ArgumentParser(description="Call OpenAI Codex/completion API with a prompt")
    parser.add_argument("--prompt", "-p", help="Prompt text (if omitted, read from stdin)")
    parser.add_argument("--model", "-m", default=os.environ.get("OPENAI_MODEL", "code-davinci-002"))
    parser.add_argument("--max-tokens", type=int, default=256)
    parser.add_argument("--env-file", help="Path to an env file to load (optional)")
    args = parser.parse_args()

    # Load env file if requested or present. Priority: --env-file, .env.local, .env
    env_file = None
    if getattr(args, "env_file", None):
        env_file = args.env_file
    else:
        for candidate in (".env.local", ".env"):
            if os.path.exists(candidate):
                env_file = candidate
                break

    if env_file and load_dotenv:
        load_dotenv(env_file)

    if args.prompt:
        prompt = args.prompt
    else:
        prompt = sys.stdin.read()
        if not prompt:
            parser.print_help()
            sys.exit(1)

    try:
        out = call_codex(prompt, args.model, max_tokens=args.max_tokens)
        print(out.lstrip("\n"))
    except Exception as exc:
        print("Error calling OpenAI API:", exc, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()

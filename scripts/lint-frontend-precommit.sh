#!/usr/bin/env bash
# Pre-commit helper: run ESLint on staged frontend files only.
# Receives paths relative to repo root (e.g. services/frontend/app/...).
set -e
cd "$(git rev-parse --show-toplevel)/services/frontend"
strip_prefix="services/frontend/"
rel_files=()
for f in "$@"; do
  [[ "$f" == "$strip_prefix"* ]] && rel_files+=("${f#$strip_prefix}")
done
[[ ${#rel_files[@]} -eq 0 ]] && exit 0
npx eslint --max-warnings 0 "${rel_files[@]}"

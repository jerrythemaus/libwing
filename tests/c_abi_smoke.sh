#!/usr/bin/env bash
# Compile, link, and run the published header as C11 and C++17 consumers (no console).
set -euo pipefail
LIBWING_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$LIBWING_ROOT"
cargo build --locked --manifest-path "$LIBWING_ROOT/Cargo.toml" --lib
TARGET="$(cargo metadata --no-deps --locked --format-version 1 --manifest-path "$LIBWING_ROOT/Cargo.toml" \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Generate typed references to EVERY header declaration and reject export/header drift.
# Volatile local pointers keep each reference in the linked executable without invoking it.
python3 - "$LIBWING_ROOT" "$WORK/abi_symbols.inc" <<'PY'
import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
header = re.sub(r'/\*.*?\*/|//[^\n]*', '', (root / 'libwing.h').read_text(), flags=re.S)
declarations = re.findall(r'([\w\s*]+?)\b(wing_\w+)\s*\(([^;{}]*)\)\s*;', header)
exported = set(re.findall(r'pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(wing_\w+)', (root / 'src/ffi.rs').read_text()))
names = [name for _, name, _ in declarations]
if not names or len(names) != len(set(names)) or set(names) != exported:
    raise SystemExit(f'ABI declaration mismatch: header-only={sorted(set(names)-exported)}, Rust-only={sorted(exported-set(names))}')
with open(sys.argv[2], 'w') as out:
    for result, name, args in declarations:
        out.write(f'{result.strip()} (*volatile ref_{name})({args}) = {name};\n(void)ref_{name};\n')
print(f'Checking {len(names)} exported declarations in C and C++')
PY

"${CC:-cc}" -std=c11 -Wall -Wextra -Werror -I"$LIBWING_ROOT" -I"$WORK" \
  "$LIBWING_ROOT/tests/c_abi_smoke.c" -L"$TARGET/debug" -Wl,-rpath,"$TARGET/debug" -llibwing -o "$WORK/c-smoke"
"${CXX:-c++}" -x c++ -std=c++17 -Wall -Wextra -Werror -I"$LIBWING_ROOT" -I"$WORK" \
  "$LIBWING_ROOT/tests/c_abi_smoke.c" -L"$TARGET/debug" -Wl,-rpath,"$TARGET/debug" -llibwing -o "$WORK/cpp-smoke"
"$WORK/c-smoke"
"$WORK/cpp-smoke"
echo 'PASS: C11 and C++17 exported API compile/link/use smoke'

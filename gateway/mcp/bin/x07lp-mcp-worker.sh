#!/bin/sh
set -eu

# This wrapper provides baseline policy knobs for the sandboxed x07 MCP worker.
# Tool-specific roots/allowlists are still applied by the router via X07_OS_* env vars.

export X07_OS_FS_ALLOW_MKDIR=1
export X07_OS_FS_ALLOW_RENAME=1

export X07_OS_TIME=1
export X07_OS_TIME_ALLOW_WALL_CLOCK=1
export X07_OS_TIME_ALLOW_MONOTONIC=1
export X07_OS_TIME_ALLOW_SLEEP=0
export X07_OS_TIME_ALLOW_LOCAL_TZID=0

export X07_OS_ENV=1
export X07_OS_ENV_ALLOW_KEYS='PATH;HOME;X07LP_STATE_DIR'

export X07_OS_PROC=1
export X07_OS_PROC_ALLOW_EXIT=1
export X07_OS_PROC_ALLOW_SPAWN=1
export X07_OS_PROC_ALLOW_EXEC=1
export X07_OS_PROC_ALLOW_ENV_KEYS='PATH;HOME'

if [ -z "${HOME:-}" ]; then
  user_name="$(/usr/bin/id -un 2>/dev/null || true)"
  if [ -n "${user_name}" ]; then
    if [ -d "/Users/${user_name}" ]; then
      HOME="/Users/${user_name}"
    elif [ -d "/home/${user_name}" ]; then
      HOME="/home/${user_name}"
    fi
    export HOME
  fi
fi

if [ -z "${PATH:-}" ]; then
  PATH="/usr/bin:/bin"
fi

channel=""
if [ -f "x07-toolchain.toml" ]; then
  channel="$(/usr/bin/sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' x07-toolchain.toml | /usr/bin/head -n 1)"
fi

if [ -n "${HOME:-}" ]; then
  if [ -d "${HOME}/.cargo/bin" ]; then
    PATH="${HOME}/.cargo/bin:${PATH}"
  fi
  if [ -n "${channel}" ] && [ -d "${HOME}/.x07/toolchains/${channel}/bin" ]; then
    PATH="${HOME}/.x07/toolchains/${channel}/bin:${PATH}"
  fi
fi

export PATH

x07_wasm_exe="$(/usr/bin/which x07-wasm 2>/dev/null || true)"
if [ -n "${x07_wasm_exe}" ]; then
  export X07_OS_PROC_ALLOW_EXECS="/usr/bin/env;${x07_wasm_exe}"
else
  export X07_OS_PROC_ALLOW_EXECS="/usr/bin/env"
fi

exec ./out/x07lp-mcp-worker "$@"

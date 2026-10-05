#!/bin/bash
# Explicit privileged mutation boundary. Never source policy or caller files.
set -Eeuo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export LC_ALL=C
umask 077
[[ "$EUID" == 0 && "$(/usr/bin/uname -s)" == Darwin ]] || exit 77
[[ $# -ge 2 && "$2" =~ ^com\.apple/netorch\.[a-z][a-z0-9-]{0,62}$ ]] || exit 64
op="$1"; anchor="$2"; shift 2
pf() { /sbin/pfctl "$@"; }
normalize() { /usr/bin/awk '{$1=$1; if (NF) print}'; }
shape() {
  local filters children tables
  filters="$(pf -a "$anchor" -s rules 2>/dev/null)" || return 1
  children="$(pf -a "$anchor" -s Anchors 2>/dev/null)" || return 1
  tables="$(pf -a "$anchor" -s Tables 2>/dev/null)" || return 1
  [[ -z "$filters" && -z "$children" && -z "$tables" ]]
}
hooks() {
  local rules
  rules="$(pf -s nat 2>/dev/null)"
  printf '%s\n' "$rules" | /usr/bin/grep -Eq '^rdr-anchor "com\.apple/\*"( all)?$'
  printf '%s\n' "$rules" | /usr/bin/grep -Eq '^nat-anchor "com\.apple/\*"( all)?$'
}
safe_file() {
  [[ -f "$1" && ! -L "$1" && "$(/usr/bin/stat -f '%u:%g:%Lp:%l' "$1")" == 0:0:600:1 ]]
}
case "$op" in
  inspect)
    [[ $# == 0 ]]; hooks; shape
    pf -a "$anchor" -s nat 2>/dev/null | normalize ;;
  normalize)
    [[ $# == 1 ]]; safe_file "$1"
    pf -a "$anchor" -n -v -f "$1" 2>/dev/null | normalize ;;
  replace)
    [[ $# == 2 ]]; safe_file "$1"; safe_file "$2"; hooks; shape
    expected="$(pf -a "$anchor" -n -v -f "$1" 2>/dev/null | normalize)"
    live="$(pf -a "$anchor" -s nat 2>/dev/null | normalize)"
    [[ "$expected" == "$live" ]] || exit 73
    # Parse candidate before any mutation. The parent holds the persistent lock.
    candidate="$(pf -a "$anchor" -n -v -f "$2" 2>/dev/null | normalize)"
    shape
    [[ "$(pf -a "$anchor" -s nat 2>/dev/null | normalize)" == "$live" ]] || exit 73
    pf -a "$anchor" -f "$2" >/dev/null 2>&1 || true
    shape
    after="$(pf -a "$anchor" -s nat 2>/dev/null | normalize)"
    [[ "$after" == "$candidate" ]] || exit 74
    # Exact candidate readback is authoritative even when pfctl reports an error.
    printf '%s\n' "$after" ;;
  states)
    [[ $# == 0 ]]; pf -s states 2>/dev/null ;;
  drain)
    [[ $# == 1 && "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
    # Scoped source/destination invalidation; never flush global state.
    pf -k "$1" >/dev/null 2>&1
    pf -k 0.0.0.0/0 -k "$1" >/dev/null 2>&1 ;;
  enable)
    [[ $# == 0 ]]; pf -E 2>&1 ;;
  enabled)
    [[ $# == 0 ]]; pf -s info 2>/dev/null | /usr/bin/grep -Eq '^Status: Enabled([[:space:]]|$)' ;;
  references)
    [[ $# == 0 ]]; pf -s References 2>/dev/null ;;
  release)
    [[ $# == 1 && "$1" =~ ^[0-9]{1,20}$ ]]; pf -X "$1" >/dev/null 2>&1 ;;
  *) exit 64 ;;
esac

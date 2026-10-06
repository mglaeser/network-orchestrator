#!/bin/bash
# Explicit privileged mutation boundary. Never source policy or caller files.
#
# Keep this file valid for the bash 3.2 that macOS installs as /bin/bash. Under
# `set -e` that version ends the script after a failing simple command but not
# after a failing `[[ ... ]]`, so no check below relies on it: every `[[ ... ]]`
# is the condition of an `if` or is followed by its own `|| exit`/`|| return`,
# and every function call and pipeline that must succeed says so as well.
set -Eeuo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export LC_ALL=C
umask 077
[[ "$EUID" == 0 && "$(/usr/bin/uname -s)" == Darwin ]] || exit 77
[[ $# -ge 2 && "$2" =~ ^com\.apple/netorch\.[a-z][a-z0-9-]{0,62}$ ]] || exit 64
op="$1"; anchor="$2"; shift 2
pf() { /sbin/pfctl "$@"; }
normalize() { /usr/bin/awk '{$1=$1; if (NF) print}'; }
# A listing that names no anchor: states, status, references, the main hooks.
# pfctl can end such a listing with exit status 0 after only a warning, and an
# empty answer would then pass for an empty table. So besides the exit status,
# anything on standard error fails the read, except the two notices about ALTQ
# that pfctl writes on every call. Standard output is passed on unchanged.
unexpected() {
  /usr/bin/grep -Fxv -e 'No ALTQ support in kernel' -e 'ALTQ related functions disabled'
}
listing() {
  local warnings status
  status=0
  { warnings="$( { pf "$@" 1>&3; } 2>&1 )" || status=$?; } 3>&1
  if [[ "$status" != 0 ]]; then return 1; fi
  # grep reports 1 when it passed nothing on; a higher status is its own failure.
  warnings="$(printf '%s\n' "$warnings" | unexpected)" || status=$?
  if [[ "$status" -gt 1 || -n "$warnings" ]]; then return 1; fi
}
# Reads of the owned anchor cannot use that rule. The anchor does not exist
# before its first load, the kernel then refuses the listing, and what pfctl
# writes about that is not published: an empty anchor and a missing one must
# read alike. These reads check the exit status only.
owned() { pf -a "$anchor" -s nat 2>/dev/null | normalize; }
shape() {
  local filters children tables
  filters="$(pf -a "$anchor" -s rules 2>/dev/null)" || return 1
  children="$(pf -a "$anchor" -s Anchors 2>/dev/null)" || return 1
  tables="$(pf -a "$anchor" -s Tables 2>/dev/null)" || return 1
  if [[ -n "$filters" || -n "$children" || -n "$tables" ]]; then return 1; fi
}
# `grep -q` leaves at its first match. Fed through a pipe, a writer that has not
# finished then dies of SIGPIPE, and `pipefail` reports a check that succeeded
# as failed. A here-string is complete before grep starts.
hooks() {
  local rules
  rules="$(listing -s nat)" || return 1
  /usr/bin/grep -Eq '^rdr-anchor "com\.apple/\*"( all)?$' <<<"$rules" || return 1
  /usr/bin/grep -Eq '^nat-anchor "com\.apple/\*"( all)?$' <<<"$rules" || return 1
}
# Owner, mode and link count are what the caller's private write guarantees.
# The group is not compared: a new file takes the group of its directory, which
# need not be 0, and with mode 0600 the group has no access to the file.
safe_file() {
  if [[ ! -f "$1" || -L "$1" ]]; then return 1; fi
  [[ "$(/usr/bin/stat -f '%u:%Lp:%l' "$1")" == 0:600:1 ]] || return 1
}
case "$op" in
  inspect)
    if [[ $# != 0 ]]; then exit 64; fi
    hooks || exit 1
    shape || exit 1
    owned || exit 1 ;;
  normalize)
    if [[ $# != 1 ]]; then exit 64; fi
    safe_file "$1" || exit 1
    pf -a "$anchor" -n -v -f "$1" 2>/dev/null | normalize || exit 1 ;;
  replace)
    if [[ $# != 2 ]]; then exit 64; fi
    safe_file "$1" || exit 1
    safe_file "$2" || exit 1
    hooks || exit 1
    shape || exit 1
    expected="$(pf -a "$anchor" -n -v -f "$1" 2>/dev/null | normalize)" || exit 1
    live="$(owned)" || exit 1
    [[ "$expected" == "$live" ]] || exit 73
    # Parse candidate before any mutation. The parent holds the persistent lock.
    candidate="$(pf -a "$anchor" -n -v -f "$2" 2>/dev/null | normalize)" || exit 1
    shape || exit 1
    # Read again immediately before loading. The status of this read is checked
    # before the comparison: a failed read must not pass for an empty anchor.
    current="$(owned)" || exit 1
    [[ "$current" == "$live" ]] || exit 73
    pf -a "$anchor" -f "$2" >/dev/null 2>&1 || true
    shape || exit 1
    after="$(owned)" || exit 1
    [[ "$after" == "$candidate" ]] || exit 74
    # Exact candidate readback is authoritative even when pfctl reports an error.
    printf '%s\n' "$after" ;;
  states)
    if [[ $# != 0 ]]; then exit 64; fi
    listing -s states || exit 1 ;;
  drain)
    if [[ $# != 1 ]]; then exit 64; fi
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 64
    # Scoped source/destination invalidation; never flush global state.
    pf -k "$1" >/dev/null 2>&1 || exit 1
    pf -k 0.0.0.0/0 -k "$1" >/dev/null 2>&1 || exit 1 ;;
  enable)
    if [[ $# != 0 ]]; then exit 64; fi
    pf -E 2>&1 || exit 1 ;;
  enabled)
    if [[ $# != 0 ]]; then exit 64; fi
    info="$(listing -s info)" || exit 1
    /usr/bin/grep -Eq '^Status: Enabled([[:space:]]|$)' <<<"$info" || exit 1 ;;
  references)
    if [[ $# != 0 ]]; then exit 64; fi
    listing -s References || exit 1 ;;
  *) exit 64 ;;
esac

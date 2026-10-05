# Native scheduling, generated from deployment data

`netorch deploy render` generates plists from `deployment.json`; this directory
contains no second editable copy of labels, account IDs or commands. Python's
standard `plistlib` creates correctly escaped deterministic XML.

The declared user jobs are installed only in the declared user's LaunchAgents
directory and `gui/UID` domain. The independent forwarding job is installed only
by a separate administrator invocation in `system`. Its fixed command pulls the
root-owned forwarding snapshot. The coordinator cannot call it or supply a plan.

Periodic tasks use `StartInterval`, `RunAtLoad` and a throttle. Long-lived Bonjour
and Monit processes use `KeepAlive` without a competing interval. Jobs get a
minimal environment, private umask and separate logs. Launchd creates a process;
it does not supply Bonjour privacy consent or prove application readiness.

The installer checks ownership of existing files and whether a new label is
already loaded before any stop operation. It uses `bootout`, `bootstrap` and
`print` only for its declared jobs. It never changes Apple runtime launch jobs,
Login Items, automatic login or application LaunchAgents. Hardware acceptance
must use the actual user job identity after login and reboot.

Native reference: [launchd.plist(5)](https://keith.github.io/xcode-man-pages/launchd.plist.5.html).

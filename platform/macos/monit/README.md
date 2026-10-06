# Monit schedules checks; existing owners decide recovery

The deployment renderer creates one private `monitrc` and launchd runs the
maintained Monit executable in foreground mode. The executable/version is
operator-managed; Netorch never installs or upgrades Monit implicitly.

Each check calls an explicitly declared owner command. Only status **42** for
the configured cycle count can execute the declared workload recovery command.
Ordinary failure, signals, timeout, malformed/incomplete observations, permission
denial, busy locks and stale evidence cannot match this rule. A start command
must reobserve the workload and independently preserve pause/suspension gates.

By default the rule runs the recovery command once per failure episode. When a
workload monitor sets `recovery_repeat_cycles`, its rule ends in
`repeat every N cycles` and Monit runs the command again every N cycles while
the probe still returns 42. The repeat has no upper count; each run is the same
guarded start.

Forwarding and discovery checks can alert, but cannot have a recovery command.
A PF failure therefore cannot restart a container. Bonjour's own registration
watchdog enforces its lease; Monit is not the lease clock. A single existing
lifecycle owner remains responsible for each workload; this configuration must
replace competing recovery schedules only after their ownership is reviewed.

Monit PID, identity and state files live under persistent state outside the
release. The installer runs `monit -t` before stopping old jobs. Its native
syntax-check success establishes grammar only; fake process tests establish
ordering and failure behavior without invoking native networking.

Native reference: [Monit manual](https://mmonit.com/monit/documentation/monit.html).

# Diagnostics
`POST /saltboot/diagnostics` collects read-only diagnostics on a node; `POST /saltboot/diagnostics/distribute` fans the
request out to `targets`. Both use the same Basic auth and signature as the other routes and run a fixed set of probes only:
- salt-bootstrap and salt-minion (and, where installed, salt-master/salt-api) unit state, plus the request's `additionalUnits`: up to 20 plain systemd
  unit names (no leading `-`, no globs; a trailing `.service` is dropped, so `nginx.service` is reported as `nginx`), reported even when the unit is not found; a unit beyond the limit or with an
  invalid name is not probed but listed with a `rejected` reason, and the rest of the request still runs;
- the masters in `/etc/salt/minion.d/master.conf`, the minion id and key fingerprint, the fingerprints of the master key
  (and sign key) a minion holds and a TCP check to every master on 4505/4506;
- on salt-master nodes the known minion keys with their state (accepted, pending, rejected, denied), the fingerprint of
  every accepted key and the master's own key and sign key fingerprints, which are comparable with the ones on the minions;
- the `saltuser` account salt-api logs in with: locked, empty or expired password, expiry dates, account expiry,
  forced change, an interrupted rotation (`/etc/shadow.new`), faillock failures and the mode of `/etc/passwd`,
  `/etc/shadow` and `/etc/group` (never the password hash);
- host identity: hostname, FQDN and what it resolves to, interface addresses, `/etc/hosts` entries of the node and
  `resolv.conf`; salt and python version of the running salt-minion/salt-master;
- salt jobs: the proc files of the salt-minion and, where the directory exists, of the salt-master
  (`/var/cache/salt/{minion,master}/proc`) with the start time and age taken from the job id (the oldest 100 are listed,
  the rest is counted), and `worker_threads` from `/etc/salt/master` and `/etc/salt/master.d/*.conf` (the last value wins);
- NTP sync, load, memory with OOM kills, boot time, free space and inodes
  of `/` and of `/var`, `/var/log`, `/srv`, `/tmp` and `/opt` where they are mounts of their own, LVM volume groups and
  logical volumes from `vgs`/`lvs` (read-only, 5s timeout; skipped without lvm2) with the mount points, free space and inodes of the
  mounted ones;
- the redacted last `logLines` (default 50, max 200) lines of `/var/log/salt/minion`, `/var/log/saltboot.log` and,
  where they exist, `/var/log/salt/master` and `/var/log/salt/api`.
```
{"targets": ["10.0.0.1", "10.0.0.2"], "logLines": 50, "additionalUnits": ["chronyd", "node-exporter"], "probeDeadline": "10s"}
```
The fan-out contacts at most `maxParallelTargets` (default 50) targets at a time, the others in request order as slots
free up, and waits `distributeTimeout` (default 20s) per target, counted from when the target is contacted, so with many
slow targets the call can take `ceil(targets / maxParallelTargets) × distributeTimeout`; an unreachable node, or one running
an older salt-bootstrap without the route (404), is reported with its `statusCode` and `errorText`. `probeDeadline` is how
long every node collects; the request reaches the nodes unchanged, so all of them use it, and the distribute route
rejects one that leaves less than 1s of its `distributeTimeout` for the response; the deadline also covers reading the logs. Without it, each node uses the `probeDeadline` of its own
configuration. Every node reports the deadline it used and a `configFingerprint` of its configuration.
`saltUserPassword` (optional) is the expected saltuser password: every node with a saltuser entry re-hashes it
with the salt in `/etc/shadow` and reports `saltUser.passwordCheck` (`match`, `mismatch`, or `unverifiable` for a hash
other than the sha512 salt-bootstrap writes, e.g. the yescrypt of `passwd` on RHEL 9) next to `passwordHashScheme`. The
password is never logged or returned, but the request reaches every target, so send it only when needed. `salt-user`
fails when the password does not match, and warns when it cannot be checked.

The distribute response also holds `checks`, the findings across the nodes, one entry per id in this order, each with a
`status` (`ok`, `warn`, `fail`, `skipped` when the data is missing, e.g. no salt-master among the targets, or `error` when the check itself failed, which does not affect the other checks), a short
`message` naming the nodes and the `nodes` involved: `node-reachable`, `timed-out-probes`, `config-consistent` (fails for a
node whose probe deadline leaves less than 1s of the fan-out node's `distributeTimeout` for the response, as it would be reported unreachable, and
warns for nodes whose configuration differs from the fan-out node's or could not be used), `salt-units`,
`additional-units` (the requested `additionalUnits` that are no salt units; a unit that is not active only warns, a
rejected one fails, the same problem on several nodes is one finding; skipped when none are requested), `master-ports`,
`master-keys-consistent`, `minion-master-key`, `minion-key-accepted`, `unknown-accepted-keys` (a warning is expected if only a
subset of the cluster is targeted), `minion-id`, `host-resolution`, `salt-version`, `salt-user`, `salt-jobs`, `clock` and `resources`.
Beyond the unit state, `salt-units` fails for a crash-looping salt unit (`additional-units` warns for a requested one):
active, but restarted at least `crashLoopRestarts` (3) times by systemd with a process younger than `crashLoopUptime`
(1m), as a service that exits a second after its start counts as running in between. It also warns when the main process of salt-minion, salt-master or salt-api is in `D` state (uninterruptible I/O wait), and `host-resolution` warns when `hostname -f` returns a name without a dot.
`salt-jobs` only warns: for every salt-minion or salt-master job older than 1 hour and for a salt-master with more than 25 accepted minions per worker thread (`worker_threads`, 5 if not configured); it is skipped when no node reports jobs.
`clock` warns about a node that is not NTP synchronized (or has NTP disabled) and compares the clocks of the nodes with their median, as the nodes are not probed at the same instant the tolerance is wide: a node more than 120 seconds off warns, more than 300 seconds (Kerberos rejects a skew over 5 minutes) fails. The comparison needs two nodes with a parsable time.
The checks name the nodes by host, without the salt-bootstrap port, unless two targets share a host; the `nodes` of
the response keep the address they were reached at.
The numbers above are the defaults of the diagnostics configuration (see below).
A probe that panics does not fail the call: it is listed in the node's `failedProbes` as `<probe>: <panic value>` (the other probes still answer) and reported as a warning by `timed-out-probes`.
A node counts as a salt-master if it has a `/etc/salt/pki/master` directory and its address, FQDN or hostname is one of the masters in the minions' `master.conf`; without any `master.conf` data, if its salt-master unit is active or it has a saltuser account.

## Diagnostics configuration
The limits, thresholds and lists of the diagnostics can be overridden with a YAML file at
`/etc/salt-bootstrap/diagnostics.yml`, or wherever `SALTBOOT_DIAGNOSTICS_CONFIG` points. It is read once at startup,
so a change needs a salt-bootstrap restart. Every key is optional; a key the file sets replaces the default as a whole,
a map or list included. Durations need a unit (`15s`, `2m`, `1h`); a plain number is an error. If the file cannot be
used (bad YAML, an unknown key, an invalid value), salt-bootstrap logs why and runs with all defaults, and every
diagnostics response carries the reason as `configError`. Each node uses its own file: the node running the fan-out
applies its `distributeTimeout` and the check thresholds, every node its own probe limits. The command, lookup,
salt-call, LVM and dial timeouts are cut to the probe deadline of the request, so none can outlast the collection.
```yaml
# timeouts
distributeTimeout: 20s       # how long the distribute route waits for one target
maxParallelTargets: 50       # targets the distribute route contacts at a time; the rest wait in request order
probeDeadline: 10s           # how long a node collects unless the request sets probeDeadline; unfinished probes are listed in timedOutProbes
dialTimeout: 3s              # TCP check of a master port
commandTimeout: 3s           # hostname, faillock, systemctl show
lookupTimeout: 3s            # lookup of the node's own FQDN
saltCallTimeout: 5s          # salt-call --version
lvmTimeout: 5s               # lvs / vgs
# sizes and counts
defaultLogLines: 50          # logLines when the request has none
maxLogLines: 200
logWindowBytes: 65536        # only the end of a log is read
maxLineBytes: 1024
maxAdditionalUnits: 20
maxUnitNameLength: 255
maxJobs: 100                 # salt jobs listed per node
checkTextLength: 80          # error texts quoted in check messages
checkListLength: 5           # items named in a check message before "and N more"
# check thresholds
lowFreeWarnPercent: 10       # free space or inodes
lowFreeFailPercent: 2
loadPerCpuWarn: 2
clockSkewWarn: 2m
clockSkewFail: 5m
jobAgeWarn: 1h
defaultWorkerThreads: 5      # salt-master worker_threads when it has none configured
minionsPerWorkerThread: 25
passwordExpiryWarnDays: 14   # saltuser
crashLoopRestarts: 3         # an active unit restarted this often by systemd whose process is younger than
crashLoopUptime: 1m          # crashLoopUptime is crash-looping
# lists; units and logFiles map a name to whether it is required (an optional one is left out where it is missing)
units: {salt-bootstrap: true, salt-minion: true, salt-master: false, salt-api: false}
logFiles: {/var/log/salt/minion: true, /var/log/saltboot.log: true, /var/log/salt/master: false, /var/log/salt/api: false}
masterPorts: [4505, 4506]
mountPoints: [/var, /var/log, /srv, /tmp, /opt]
```

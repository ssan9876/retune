# Sizing a Retune server

What decides how big a server needs to be is **check-ins per second**: each
device checks in every `CHECKIN_INTERVAL_SECONDS` (300 by default), so

> check-ins per second = devices ÷ interval in seconds

A 10,000-device fleet at the default interval makes about 33 a second; 50,000
makes about 167. Everything else a server does — inventory uploads (only when
a device's inventory changed, or once a day), results, the console, the
sweeper — is small beside that.

## What was measured

`retune-loadsim` (below) enrolled simulated devices against a real server and
had them check in on a shortened interval, so that a few thousand devices made
the load of a much larger fleet. Each device sent a 150-program inventory the
first time it was asked, and its inventory hash after that, as an agent does.

The server, PostgreSQL 17 and the simulator all ran on **one desktop**: 16
hardware threads, PostgreSQL in Docker Desktop, default settings everywhere
(including pgx's pool of one connection per thread). A real deployment, with
the database on its own machine and nothing generating load beside it, will
do at least as well.

| check-ins per second | fleet at the 5-minute default | check-in p50 | p95 | p99 | failures |
|---:|---:|---:|---:|---:|---:|
| 17 | 5,000 | 8 ms | 12 ms | 15 ms | 0 |
| 67 | 20,000 | 8 ms | 13 ms | 22 ms | 0 |
| 154 | 46,000 | 8 ms | 14 ms | 32 ms | 0 |
| 227 | 68,000 | 9 ms | 268 ms | 754 ms | 0 |
| 322 | 97,000 | 9 ms | 758 ms | 2.5 s | 0 |

Enrolment ran at about 145 devices a second with 50 at a time (345 ms each,
most of it the server signing a certificate). An inventory upload of this size
took 55–65 ms until the knee.

Past about 200 check-ins a second, requests start queuing and the tail
stretches; nothing failed even at 322 a second, but a device then waits
seconds for a check-in. The database held 9,000 devices in 208 MB, about
23 KB a device with 150 programs each.

## Recommendations

Plan for half of the knee, so a burst — every device coming back after a
network outage, or a new assignment everyone fetches at once — has room:

| fleet | server | database |
|---|---|---|
| up to 10,000 | 2 vCPU, 4 GB | on the same machine is fine; 2 GB for PostgreSQL |
| up to 30,000 | 4 vCPU, 8 GB | its own machine, 4 vCPU, 8 GB, SSD |
| up to 50,000 | 8 vCPU, 8 GB | its own machine, 8 vCPU, 16 GB, SSD |
| beyond | measure first | — |

Beyond 50,000, lengthen the check-in interval before adding hardware: at 10
minutes the same server carries twice the fleet, at the cost of commands and
assignments taking up to 10 minutes to arrive. Budget 25–50 KB of database per
device, plus history (the retention settings bound it), and disk for uploaded
agent builds and app packages.

These are measurements of one machine, not guarantees. Measure your own
before a large rollout.

## Measuring your own

`retune-loadsim` enrols devices against a server and reports latency per
operation. Point it at a **server set up for the purpose** — every simulated
device stays enrolled, as `LOADSIM-…` hostnames — never production.

```sh
go build -o retune-loadsim ./cmd/retune-loadsim
retune-server ca cert > ca.pem
retune-server token create --max-uses 2000 --label loadtest   # prints the token
retune-loadsim --server https://test-retune:8443 --ca ca.pem --token <token> \
  --devices 2000 --interval 13s --duration 5m
```

`--interval` is the lever: 2,000 devices every 13 seconds is the check-in rate
of 46,000 at the default interval. Raise it in steps and watch p95 and p99;
the knee is where they leave p50 behind. Run the simulator on a different
machine from the server if you can: on the same one, it competes for the CPU
it is measuring.

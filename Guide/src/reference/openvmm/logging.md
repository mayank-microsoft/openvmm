# OpenVMM Logging

## Configuring OpenVMM logging messages to emit

To configure logging, set the `OPENVMM_LOG` environment variable. The default
level is `info`. For example:

- `OPENVMM_LOG=debug` — enable debug events from all modules
- `OPENVMM_LOG=info,mesh=trace` — enable trace events from the `mesh` crate
  and info events from everything else

This is backed by the
[`EnvFilter`](https://docs.rs/tracing-subscriber/0.2.17/tracing_subscriber/struct.EnvFilter.html)
type; see the associated documentation for more details.

### Span events

By default, OpenVMM does not log span enter/exit events. To enable them, set
`OPENVMM_LOG_SPANS=1`.

### Rate limiting

Trace events that can be triggered repeatedly by guest interactions are
rate-limited by default. To disable rate limiting (useful for debugging), set
`OPENVMM_DISABLE_TRACING_RATELIMITS=1`.

### OpenTelemetry

Build OpenVMM with the `otel` feature, then set `OPENVMM_OTEL=1` to emit
enabled spans through the platform's native tracing subsystem: ETW on Windows
and `user_events` on GNU/Linux. Other platforms do not currently have a native
OpenTelemetry trace sink. For example:

```shell
cargo build -p openvmm --features otel

OPENVMM_OTEL=1 \
OTEL_RESOURCE_ATTRIBUTES="service.instance.id=boot-test-42" \
target/debug/openvmm [...]
```

The native events preserve OpenTelemetry trace and span identifiers. They are
not sent directly to an OpenTelemetry Collector or Jaeger; a platform-specific
agent must collect and forward them. Windows emits `Span` events from provider
`openvmm`, and Linux emits the `user_events:openvmm_L4K1` tracepoint. On Linux,
the process must have write access to the tracefs `user_events_data` file;
OpenTelemetry initialization fails if `user_events` is unavailable or not
writable.

### Boot performance spans

With OpenTelemetry enabled, spans on the `openvmm::perf` target show VM
configuration, worker-host creation, hypervisor selection, worker launch, and
the resume RPC in the controller. The VM worker traces partition creation,
guest memory build and attachment, base and final chipset construction,
partition-unit setup, firmware loading, PCI resource assignment, initial VP
registers, and resume. KVM and MSHV use the same span names for partition
creation, build, and VP binding; each has a `backend` attribute, and binding
spans include `vp_index`. Backend-specific spans show VM/VCPU creation and
MSHV partition initialization. `first_bsp_run` marks the first attempt to
run the boot VP, **not** guest OS readiness.

MSHV also emits per-range memory mapping spans at its regular tracing target;
KVM does not have matching per-range spans. Use
`guest_memory_attach_partition` for a backend-neutral mapping duration.

Use the same guest configuration with `--hypervisor kvm` and
`--hypervisor mshv`, and collect `user_events` before launching OpenVMM to
capture startup.
The controller and VM worker normally run in separate processes; their spans
do not automatically share an OpenTelemetry trace ID. Correlate them by the
collection run and process, for example by setting a distinct
`OTEL_RESOURCE_ATTRIBUTES="service.instance.id=boot-run-1"` for each launch.
Performance spans are excluded from stderr logging even when
`OPENVMM_LOG_SPANS=1`.

## Configuring OpenHCL Trace Logging

OpenHCL also supports `EnvFilter`-style trace logging, configured via the
`-c OPENVMM_LOG=` command line argument. The `-c` flag passes arguments to
OpenHCL initialization. The filter syntax is the same as for OpenVMM.

OpenHCL tracing can also be configured and dumped at runtime with
`ohcldiag-dev`. See: [OpenHCL Diagnostics](../openhcl/diag/ohcldiag_dev.md)

To retrieve OpenHCL log output at runtime, an output console or file must
attach to the OpenHCL logging COM port. By default, OpenHCL outputs to `COM3`.

To open a new terminal window with global OpenHCL debug level tracing enabled:

```shell
openvmm -c "OPENVMM_LOG=debug" --com3 "term,name=VTL2 OpenHCL" [...]
```

Configure log levels of only a given module name:

```shell
openvmm -c "OPENVMM_LOG=mesh=trace" --com3 "term,name=VTL2 OpenHCL" [...]
```

Multiple modules can be specified by separating them with a comma:

```shell
openvmm -c "OPENVMM_LOG=mesh=trace,nvme_driver=trace" \
    --com3 "term,name=VTL2 OpenHCL" [...]
```

```admonish tip
For more configuration examples of serial ports and the OpenVMM CLI, see the
[Running OpenHCL Guide](../../../user_guide/openhcl/run/openvmm.md) and CLI
`--help` output.
```

## Capturing the ETW traces on the host

On Windows, OpenVMM also logs to ETW, via the Microsoft.HvLite provider.

To capture the trace, start a session:

```powershell
logman start trace <SESSION_NAME> -ow -o trace.etl `
    -p "{22bc55fe-2116-5adc-12fb-3fadfd7e360c}" 0xffffffffffffffff 0xff `
    -nb 16 16 -bs 16 -mode 0x2 -ets
```

```admonish note
For OpenHCL traces, use `{AA5DE534-D149-487A-9053-05972BA20A7C}` as the
provider GUID.
```

To flush:

```powershell
logman update <SESSION_NAME> -ets -fd
```

To stop:

```powershell
logman stop <SESSION_NAME> -ets
```

To decode as CSV:

```powershell
tracerpt trace.etl -y -of csv -o trace.csv -summary trace-summary.txt
```

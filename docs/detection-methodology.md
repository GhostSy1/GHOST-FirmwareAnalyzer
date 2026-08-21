# Detection Methodology

## Interpretation rule

The analyzer reports observable evidence. It does not convert a string match into a claim of exploitability. Analysts should correlate each finding with the device model, release version, expected feature set, build manifest, and independent acquisition records.

## Rule catalog

| Rule ID | Observation | Default severity | Confidence | Next action |
|---|---|---:|---:|---|
| `FW-SVC-TELNET` | Telnet daemon marker | high | medium | Confirm exposure and replace with an authenticated encrypted channel |
| `FW-SVC-DROPBEAR` | Dropbear marker | medium | low | Identify version and review authentication and exposure |
| `FW-CRED-DEFAULT` | Default-credential phrase | high | medium | Confirm whether a live/default credential is present and rotate it |
| `FW-CRED-AUTHKEY` | SSH authorization or private-key marker | critical | high | Treat confirmed material as compromised and rotate it |
| `FW-SHELL-EXEC` | Shell or command-execution marker | medium | low | Review ownership, authorization, and exposed interfaces |
| `FW-PROTO-HTTP` | HTTP endpoint or protocol marker | low | low | Inventory endpoint and validate transport security |
| `FW-PROTO-MQTT` | MQTT or common broker-port marker | low | low | Review broker authentication, topic policy, and TLS |
| `FW-PROTO-TFTP` | TFTP marker | medium | low | Disable or isolate unauthenticated recovery paths |
| `FW-PROTO-UBUS` | Embedded management-bus marker | medium | low | Review local and network-facing management access |
| `FW-PROTO-RAW-SOCKET` | Raw packet interface marker | medium | low | Confirm least-privilege need for packet access |
| `FW-HW-JTAG` | JTAG, SWD, test-point, or debug-enable marker | high | low | Validate physical debug lock state on the board |
| `FW-HW-UNSIGNED` | Signature or secure-boot marker | high | low | Validate the actual boot chain and key policy |
| `FW-HW-DEBUG-ENV` | GDB, tracing, or debug filesystem marker | medium | low | Remove or protect development diagnostics |
| `FW-HW-BACKDOOR-TERM` | Backdoor or covert-channel term | high | low | Escalate to hardware and provenance validation |

The catalog is deliberately conservative. Severity describes the consequence if the observation is confirmed in context. Confidence describes how strongly the current static evidence supports the observation. These fields must not be conflated.

## Hardware backdoor limitations

A generic firmware file cannot reveal every hardware-level behavior. It cannot inspect undocumented silicon gates, a modified ROM, a malicious FPGA image, manufacturing straps, hidden debug fuses, or a physical implant. It can only identify static clues that justify a stronger investigation.

A high-confidence hardware conclusion should require multiple independent evidence sources, such as a trusted vendor digest, reproducible-build comparison, boot-chain measurements, debug-fuse inspection, controlled board traffic, and a documented chain of custody.

## False-positive handling

A finding should be closed as benign only after the reviewer records why the component is expected, which version was checked, and which control prevents abuse. The tool intentionally keeps the evidence excerpt and source location so that the reviewer can reproduce the decision.

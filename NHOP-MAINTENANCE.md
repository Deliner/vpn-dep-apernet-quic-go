# N-hop maintained HTTP/3 receive buffering

This branch starts at the exact Xray dependency revision
`184d081eef3e9edd5cb7c0ddf2460c91f2e6adb1`. Upstream licenses and notices remain intact.

The fixed 32-datagram HTTP/3 stream queue drops packets during a MASQUE CONNECT-IP
burst. An isolated Linux fault experiment correlated missing synthetic UDP packet
IDs and timestamps with this exact queue's drop branch. Other kernel and runtime
losses were also observed; this change does not claim to resolve all of them.

`Stream.SetDatagramReceiveBuffer` and `RequestStream.SetDatagramReceiveBuffer` allow
the tunnel owner to opt in per stream. Both packet count and payload bytes bound
the queue; empty datagrams still consume one slot. Limits are validated, allocation
is lazy, and a rejected shrink leaves data and policy unchanged. The ring releases
payload references when consumed. The default remains 32 datagrams. No network
protocol, global transport setting, kernel buffer, or other stream is changed.

This remains an unreliable datagram API: exceeding either budget drops incoming
data, and lower-level QUIC/kernel limits still apply. Applications must choose
budgets consistent with their authenticated session and memory limits.

`TestDatagramBurstWithinConfiguredBudget` fails on the baseline at packet 32/256
and passes with an explicit 1024-packet / 1 MiB budget. Tests also cover byte and
empty-packet limits, FIFO through ring growth/shrink, rejected policy changes,
released payload references, stream isolation, public API forwarding, and
concurrent configuration / enqueue / receive. The complete HTTP/3 test package
passed with the race detector under Go 1.27.3 on macOS ARM64. Native Linux Xray
integration and release acceptance remain separate requirements.

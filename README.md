# TLS Client Hello Tools

Used for this blog post: https://journal.paul.querna.org/articles/2012/09/07/adoption-of-tls-extensions/

# Usage Example
```sh

git clone https://github.com/pquerna/tls-client-hello-stats.git
cd tls-client-hello-stats

# Let tcpdump run for awhile, press ctrl+c to stop capturing.
sudo tcpdump -i eth0 -s 0 -w port443.cap port 443

python parser.py port443.cap
```

# Output Example

```
Client Hello seen: 1187
SSL v3 Clients: 0%
TLS v1 Clients: 31.76%
TLS v1.1 Clients: 33.53%
TLS v1.2 Clients: 34.71%
Sent SessionID: 0%
Deflate Support: 29.40%
Support for ec_point_formats extension: 69.92%
Support for elliptic_curves extension: 69.92%
Support for heartbeat extension: 69.50%
Support for next_protocol_negotiation extension: 10.03%
Support for renegotiation_info extension: 0.34%
Support for server_name extension: 35.21%
Support for session_tickets extension: 77.76%
Support for signature_algorithms extension: 34.71%
Support for unknown extension: 20.39%
Sent 0 extension: 20.47%
Sent 1 extension: 2.02%
Sent 2 extension: 7.58%
Sent 4 extension: 35.21%
Sent 5 extension: 4.13%
Sent 6 extension: 4.97%
Sent 7 extension: 25.61%
```

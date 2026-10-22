# Root hints

`root.hints` is the public root-name-server bootstrap file from:

https://www.internic.net/domain/named.root

Refresh it from that source, inspect the change, validate the resolver configuration, and reload. DNSSEC trust anchors are supplied separately by Hickory's built-in root keys or the configured trust-anchor file.

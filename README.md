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

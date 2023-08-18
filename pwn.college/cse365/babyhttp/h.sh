#!/usr/bin/bash

# curl http://127.0.0.1:80/40d951dcc57a1661bdd007a8d64957f4 --cookie "session=eyJzdGF0ZSI6MX0.Y5IzTQ.q67wEEmlm4FTiXj1N9M58iJ6kCw"
# curl http://127.0.0.1:80/40d951dcc57a1661bdd007a8d64957f4 --cookie "session=eyJzdGF0ZSI6Mn0.Y5IzYw.VOpL_bVT0BO15aU5npcNYj9bbaQ"
# curl http://127.0.0.1:80/40d951dcc57a1661bdd007a8d64957f4 --cookie "session=eyJzdGF0ZSI6M30.Y5Izhw.H6JcZIMnRwFRE5vMUglUPYw1hE0"

payload="{\"a\": \"ac803ead6c08d3ed72785d898be4e216\", \"b\":{\"c\": \"4c157bdb\", \"d\": [\"e80467e5\", \"7c10b51c a8f75fbb&5bd11892#4f3ee45c\"]}}"
request="GET /c80bd74fa604397a3fbf456bc2dde1ec HTTP/1.1\r\nCookie: session=eyJzdGF0ZSI6MX0.Y5Iz9A.DGNqm9VdoSFHYFl4ic-ypCCOkjk; Path=/\r\n\r\n"
state2="GET /c80bd74fa604397a3fbf456bc2dde1ec HTTP/1.1\r\nCookie: session=eyJzdGF0ZSI6Mn0.Y5I0AA.KtElAPv6xdym1SLJMuI2f0yEAH8; Path=/\r\n\r\n"
state3="GET /c80bd74fa604397a3fbf456bc2dde1ec HTTP/1.1\r\nCookie: session=eyJzdGF0ZSI6M30.Y5I0Tw.EX5H6rhLP4ALdtekF2hte1kAdJg; Path=/\r\n\r\n"
echo -ne "$request" | nc localhost 80
echo -ne "$state2" | nc localhost 80
echo -ne "$state3" | nc localhost 80


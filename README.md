![shrimp logo](https://raw.githubusercontent.com/ipv6rslimited/shrimp/main/shrimp.png)

# shrimp

**shrimp** is a simple forward proxy written in GoLang, that does not decrypt traffic, making it secure and easy to configure. It features a locked-down mode which limits it to a single network interface and IPv6 stack.

## Backstory

We were packaging an appliance with one of the most popular forward proxy solutions out there, Squid, and things were going smoothly. However, we ran into an obstacle that could not be resolved so easily - disabling dns resolution.
We found the answer - that disabling the internal dns is a pre-compile time configuration option. We quickly downloaded the libraries required and built the daemon. This build took quite a long time, and it made us curious.

That's when we began looking deeper - and we realized that for our use case, Squid and it's > 100,000 lines of code was too much to audit. We didn't need inspection, decryption, and all the other wide varieties of use cases Squid incorporates.
We thought since we already built [delorean](https://github.com/ipv6rslimited/delorean) which already powers the [IPv6rs](https://ipv6.rs) network, why not just build our own using code from there.

Shrimp only covers 1 of the 100s of brilliant use cases of Squid, but it does it pretty well - it's fast, it's lightweight and staright forward, which makes it easily auditable, just like a shrimp.

## Shrimp Features

Don't let shrimp's size fool you. In Brazilian Jiu Jitsu, when you're on your back, the shrimp is the movement to get out from under your opponent, just like shrimp.

- Forward Proxy for HTTP and HTTPS (yes, websockets works flawlessly too)
- No decryption/SSL Bumping/etc.
- Can be locked down to a single interface and IPv6
- Supports BASIC authentication, bcrypt hashed
- Utilizes an LRU cache for DNS lookups to improve performance.
- Highly scalable using goroutines.
- Super simple configuration
- IPv4 to ipv6 translation for http://2.2.2.2 type URLs
- **< 700 lines of code so you can read it and see what's going on**

## Use Case

- If you're a VPN provider and need a lightweight forward proxy with bcrypt hashed passwords
- If you're an IPv6rs client and want to make a shared proxy because sharing is caring or plausible deniability
- If you need a lightweight, super fast forward web proxy

## Requirements

- This runs on linux. It may run on mac, but you can just run it with Cloud Seeder on Windows, Mac and Linux.

## Configuration

```
{
  "listenAddrs": ["[::]:443"],
  "plaintextAddr": "0.0.0.0:3128",
  "lockdownMode": true,
  "ipv6Interface": "wg0",
  "dns64Server": "2606:4700:4700::64",
  "credentialsFile": "/etc/shrimp/passwd",
  "debugMode": false,
  "certFile": "cert.pem",
  "keyFile": "key.pem",
  "dnsCacheCapacity": 100,
  "dnsTTL": 300,
  "ipv4Translator": "visibleip.com",
  "allowedHosts": [".*"],
  "disallowedHosts": [
    "^localhost$",
    "^127\\.0\\.0\\.1$",
    "^10\\.",
    "^172\\.(1[6-9]|2[0-9]|3[0-1])\\.",
    "^192\\.168\\."
  ]
}
```

You can use `visibleip.com` as your ipv4Translator as it is run by IPv6rs and is anycasted across 16 different locations. It's nothing special - just running [legacydns](https://github.com/ipv6rslimited/legacydns) which helps to create
domain names for IP addresses when using IPv6 + NAT64 + dns64.

## Lockdown Mode

Most use cases will have lockdown mode off. This makes it run like a standard, but fast, forward web proxy.

However, if you're an IPv6rs user, running this in lockdown mode creates intentional benefits:

- If connecting via IPv4, you will hop thru a logless reverse proxy called [delorean](https://github.com/ipv6rslimited/delorean) running on an IPv6rs router, then to shrimp and then to the internet.
- Your connection will be fully contained to the wg0 interface without any potential leakage. Say goodbye to DNS leaks, IP leaks, etc.
- Some IPv6rs clients may travel and want access to their home IP when browsing, if this is the case just turn lockdown mode off.

## Using this

- FireFox has the FoxyProxy extension which is the easiest way to use shrimp in Firefox since it supports SSL forward web proxies. You don't have to signup for their service to use their extension.
- Curl has a `-x` command line option.
- Chrome doesn't seem to support SSL forward web proxies. Only use in localhost mode.

## Tests

```
$ go test -v shrimp.go shrimp_test.go
=== RUN   TestStripPort
--- PASS: TestStripPort (0.00s)
=== RUN   TestGetHostPort
--- PASS: TestGetHostPort (0.00s)
=== RUN   TestIsIPv4Address
--- PASS: TestIsIPv4Address (0.00s)
=== RUN   TestRemoveAuthHeader
--- PASS: TestRemoveAuthHeader (0.00s)
=== RUN   TestCheckAuth
--- PASS: TestCheckAuth (0.20s)
=== RUN   TestConnectTo
--- PASS: TestConnectTo (0.10s)
=== RUN   TestLookupWithCache
--- PASS: TestLookupWithCache (0.00s)
PASS
ok  	command-line-arguments	0.303s
```

# License

Distributed under the COOL License.

Copyright (c) 2024 IPv6.rs <https://ipv6.rs>
All Rights Reserved


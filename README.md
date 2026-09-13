# NGINX Multitenant

## Contents

- [Why](#why)
- [What a tenant is](#what-a-tenant-is)
- [How it works](#how-it-works)
  - [What a tenant does not get](#what-a-tenant-does-not-get)
- [Inheritance](#inheritance)
  - [The http cache](#the-http-cache)
  - [Logging](#logging)
  - [SSL](#ssl)
- [Building](#building)
- [Quick start](#quick-start)
- [Directives](#directives)
  - [tenant_zone](#tenant_zone)
  - [tenant](#tenant)
- [Loading and reloading](#loading-and-reloading)
- [What a tenant may contain](#what-a-tenant-may-contain)
- [Variables](#variables)
- [Shared memory zones](#shared-memory-zones)
- [Upstreams](#upstreams)
- [Examples](#examples)
- [Module support](#module-support)
- [Making a module eligible](#making-a-module-eligible)
- [Implementation notes](#implementation-notes)
- [Limitations](#limitations)
- [Diagnostics](#diagnostics)

## Why

nginx was built for a configuration that changes rarely. Reloading it is
therefore deliberately thorough: `SIGHUP` re-reads and re-parses the whole
configuration, builds a new cycle from it, forks a new set of workers and
asks the old ones to shut down gracefully. For a configuration an operator
edits by hand, now and then, that is exactly the right trade.

It is the wrong trade when servers are added and removed constantly. A
hosting platform, a control plane generating per-customer configuration, a
CDN edge taking on a new property — these change one server at a time, many
times an hour, and each change pays for all of it: every `server{}` block
re-parsed, every `map` rebuilt, every SSL certificate re-read, every shared
memory zone reinitialised, and two generations of workers alive at once.
Worse, the cost grows with the size of the configuration rather than with
the size of the change, so the platforms that change most often are the ones
for which reloading hurts most. Long-lived connections make it worse again:
the old workers cannot exit until their connections end, so a platform
reloading every few seconds accumulates generations of them.

The usual workarounds all give something up. Reloading on a timer trades
latency for cost. Generating one enormous configuration and reloading it
rarely means a new customer waits. Moving the routing into njs or a Lua
handler gives up on nginx's configuration entirely, and with it everything
the directives of a module know how to do.

This branch adds **tenants**: configurations of their own, written in
separate files, loaded into shared memory, and added, changed and removed at
runtime without reloading nginx and without respawning workers. Adding one
costs a parse of one file, done by the master process into a shared memory
zone where the workers see it immediately. Nothing else in the
configuration is touched, and no worker is restarted, so the cost is that of
the change rather than that of the configuration.

Changing a tenant does not disturb the requests already using it. The new
version is parsed into a pool of its own and swapped into the index; the old
one is unlinked at once but its memory is released only when the last
request holding a reference to it is done. A request that began under the
old configuration finishes under it.

## What a tenant is

A tenant is not a server of the operator's configuration that happens to
live elsewhere. It starts from the defaults of every module, not from what
the operator wrote for their own servers, and it keeps its own variables,
upstreams, log formats and shared memory zones. What it may not create for
itself, because it would have to live in one process and a tenant lives in a
zone every worker shares, it names — and that is the whole of what the
static configuration decides for it.

## How it works

The static configuration declares a zone, the files loaded into it, and
which of its own entry points those tenants may attach to:

```nginx
http {
    tenant_zone servers:4m /etc/nginx/servers/*.conf;

    server {
        listen 443 ssl;
        server_name _;

        ssl_certificate     certs/$ssl_server_name.crt;
        ssl_certificate_key certs/$ssl_server_name.key;

        tenant servers;
        return 404;
    }
}
```

Each matching file is parsed into a pool of its own inside that zone. The
servers it defines are indexed by the address they listen on and their name,
and a request whose `Host` matches none of the static server names of its
address is looked up in that index — in the zones that entry point was
opened to, and nowhere else.

A tenant does not start from the static `http{}` level. It has an `http{}`
level of its own, holding nothing but the defaults of every module, which
its servers are merged against the way the servers of the static
configuration are merged against theirs. So an `add_header`, a
`proxy_read_timeout` or a `map` the operator wrote for their own servers has
no effect on a tenant, and the operator can change any of them without
changing how a tenant behaves.

### What a tenant does not get

A tenant cannot reach the operator's backends. An `upstream` the static
configuration declares is not visible to one, so that a tenant cannot arrive
at a backend, or at another tenant's, by guessing the name it was given:

```nginx
# static
upstream app { server 10.0.0.1:8080; keepalive 32; }

# tenant - refused
location / { proxy_pass http://app; }
```

It declares its own instead, or names a host. Neither can have cached
connections; see [Limitations](#limitations).

A few things a tenant cannot make for itself, because they belong to the
process that made them: a resolver, the file caches, a cache, an SSL
context. Those it names rather than declares, which
[Inheritance](#inheritance) is about.

## Inheritance

A tenant makes everything it uses, with one class of exception: a thing that
belongs to the process that made it. A resolver keeps sockets and timers of
one process, a file cache keeps its descriptors, an `SSL_CTX` is not pool
memory at all, and the path of a cache is walked by the cache manager. None
of these survives being put in a zone every worker shares, and none can be
made after the workers have forked, which is when a tenant arrives.

A tenant therefore **names** such a thing rather than declaring it, by
writing the directive with nothing after it — or, for a cache, with the name
of its zone:

| Directive | In a tenant | Names |
|---|---|---|
| `error_log` | nothing, or a file the static one opens | the `error_log` of the static configuration |
| `resolver` | `resolver;` | the resolver of the static `http{}` level |
| `open_file_cache` | `open_file_cache;` | the cache the static configuration made |
| `open_log_file_cache` | `open_log_file_cache;` | the same, for logs |
| `proxy_cache_path` and the other `*_cache_path` | `proxy_cache_path zone;` | a cache the static configuration declared |
| `ssl_*`, `proxy_ssl_*` | — | nothing: a context cannot be named, see below |

`error_log` is the one thing a tenant inherits without naming it. A tenant
that writes none logs to the `error_log` of the static configuration, and a
tenant that writes one may name only a file the static configuration
already opens:

```nginx
error_log logs/tenants.log info;    # a file nginx.conf opens too
```

Only the container is named. `open_file_cache_valid`, `resolver_timeout`
and the rest are policy and stay the tenant's own, with the defaults of
their module. A tenant that names none of them has no resolver and no
caches, exactly as a static configuration that declares none does.

```nginx
http {
    resolver            10.0.0.53 valid=30s;
    open_file_cache     max=4096 inactive=60s;
    open_log_file_cache max=4096 inactive=60s;

    proxy_cache_path /var/cache/nginx keys_zone=shared:10m levels=1:2;

    tenant_zone tenants:16m tenants/*.conf;

    server {
        listen 80;
        server_name _;

        tenant tenants;
        return 404;
    }
}
```

`tenants/a.conf`:

```nginx
http {
    resolver;                       # resolves at request time
    open_file_cache;                # serves files through it
    open_log_file_cache;            # writes its own log through it
    proxy_cache_path shared;        # may now name "shared"

    open_file_cache_valid 30s;      # policy of its own

    server {
        listen 80;
        server_name a.example.com;

        root /srv/a;
        access_log /var/log/nginx/a.log;

        location /api/ {
            proxy_pass  http://backend;
            proxy_cache shared;
            proxy_cache_valid 200 1m;
        }
    }
}
```

Declaring one in a tenant is refused where declaring it happens, and the
naming form is refused in the static configuration, which has nothing to
name:

```
"resolver" directive cannot be created in a tenant, only named with no address
"proxy_cache_path" directive cannot be declared in a tenant, only named by the name of its zone
"resolver" directive requires an address outside a tenant
```

### The http cache

A tenant names a cache with `*_cache_path` and then uses `proxy_cache` and
the rest as it would anywhere:

```nginx
proxy_cache_path shared;

location / {
    proxy_pass          http://backend;
    proxy_cache         shared;
    proxy_cache_valid   200 302 10m;
    proxy_cache_key     "$scheme$host$request_uri";
    proxy_cache_methods GET HEAD;
    proxy_cache_lock    on;
}
```

Every `*_cache_*` directive is the tenant's own; only the path is not.
Naming one it did not name is refused, so that a tenant cannot reach a cache
of the operator, or of another tenant, by guessing the name of its zone:

```nginx
# tenant, without "proxy_cache_path shared;"
location / { proxy_pass http://backend; proxy_cache shared; }
```
```
the cache "shared" is not named by this tenant
```

Two tenants naming the same cache **share its entries**: the keyspace is the
cache's, not the tenant's, so two tenants proxying to the same host and path
hit the same entry. Until a cache key carries the tenant, give a tenant a
cache of its own — one zone per tenant, declared statically and named by
that tenant alone — or treat caching in a tenant as unfinished.

### Logging

A tenant has log formats of its own and may write to a file of its own:

```nginx
http {
    open_log_file_cache;            # the one the operator declared

    log_format tenant '$remote_addr "$request" $status';

    server {
        listen 80;
        server_name a.example.com;

        access_log logs/a.log tenant;
    }
}
```

A `log_format` a tenant declares belongs to it, and collides with nothing
the operator or another tenant declares. A format the operator declared is
not visible to a tenant, which therefore declares every format it uses.

`access_log` needs `open_log_file_cache` to be efficient. A descriptor of
the cycle is opened before the workers fork, which a tenant arrives too
late for, so a tenant writes through the open file cache of the worker
serving the request instead. Without a cache that path still works, but
every line logged costs an `open()`, an `fstat()`, the `write()` and a
`close()`, and the descriptor is held until the request ends. Declare one
statically and name it, as above, and a worker opens each file once.

Logging to syslog is refused, a peer keeping the connection of the process
that opened it, and so is `buffer=` or `gzip=`, which belong to the
descriptor they are written through.

`error_log` is inherited rather than named: see
[Inheritance](#inheritance).

### SSL

An `SSL_CTX` is the one thing on this list a tenant cannot even name,
because what a tenant would need is not the context itself but a context
built from its own certificates and settings.

Towards a client, TLS is terminated by the static entry point, which decides
the certificate, ALPN — and so whether HTTP/2 is offered — and client
certificates. A certificate per tenant needs no tenant configuration at all,
the static server picking one by the name the client asked for:

```nginx
# static
server {
    listen 443 ssl;
    server_name _;

    ssl_certificate     certs/$ssl_server_name.crt;
    ssl_certificate_key certs/$ssl_server_name.key;

    tenant tenants;
    return 404;
}
```

Towards a backend, a tenant may `proxy_pass https://backend` and gets the
defaults of the proxying module. Every `proxy_ssl_*` directive that a
context is built from is refused; the two that name the peer of a single
connection are its own:

```nginx
location /docs/ {
    proxy_pass            https://nginx.org/en/docs/;
    proxy_ssl_server_name on;                   # allowed
    proxy_ssl_name        nginx.org;            # allowed
    # proxy_ssl_ciphers HIGH;                   # refused
    # proxy_ssl_verify  on;                     # refused
}
```

## Building

The tenant module is built by default and needs nothing of `configure`:

```
$ auto/configure
$ make
```

It can be left out, which removes the module and every directive of it:

```
$ auto/configure --without-http_tenant_module
```

Reaching a backend from a tenant needs the upstream zone module, which is
what locks the peers a tenant keeps in shared memory, so a build with
`--without-http_upstream_zone_module` refuses a tenant that proxies at all.

## Quick start

The whole of `nginx.conf`, which is an ordinary static configuration with
two directives added:

```nginx
worker_processes auto;

error_log logs/error.log;
pid       logs/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include      mime.types;
    default_type application/octet-stream;

    tenant_zone servers:4m servers/*.conf;

    server {
        listen 80;
        server_name _;

        tenant servers;
        return 404;
    }
}
```

A tenant file is not a whole nginx configuration: it holds one `http{}`
block and nothing beside it. There is no `events{}`, no
`worker_processes`, no `pid` — those configure the process, which a tenant
does not own. `servers/tenant-a.conf`:

```nginx
http {
    server {
        listen 80;
        server_name a.example.com;

        root /srv/a;
    }
}
```

Anything outside that block is refused:

```
"worker_processes" directive is not allowed here in servers/tenant-a.conf:1
```

Start nginx with a control socket, and reload the tenants after
changing, adding or removing a file:

```
$ nginx -l 127.0.0.1:8081
$ curl -X PATCH http://127.0.0.1:8081/1/control/dynamic
{"logs":[]}
```

Nothing else is needed: no reload, no signal, no worker restart. The
`logs` array carries whatever the load logged, so a file that fails to parse
reports its error in the response.

## Directives

### tenant_zone

**Syntax:** `tenant_zone name:size pattern ...;`
**Context:** `http`

Loads every file matching a `pattern` into the shared memory zone `name`.
A `pattern` is a glob, resolved relative to the prefix if it is not
absolute. The zone must be at least eight pages, and holds every tenant
loaded into it, so it has to be sized for the total.

More than one pattern may be given, and the directive may be repeated with
the name of a zone already declared to add more, the size being needed only
the first time:

```nginx
tenant_zone tenants:16m tenants/*.conf staging/*.conf;
tenant_zone tenants     extra/*.conf;
```

Several zones may be declared, each with its own size and its own files:

```nginx
tenant_zone tenants:16m tenants/*.conf;
tenant_zone internal:1m internal/*.conf;
```

If two patterns of the same zone match one file, it is loaded once. If
patterns of different zones do, it is loaded into both, and which one
answers depends on the order the entry point names them in.

### tenant

**Syntax:** `tenant name;`
**Context:** `http`, `server`

Opens this entry point to the tenants of the zone `name`. A `Host` that no
static server of the address serves is looked up in the zones named here, in
the order they are named, and the first match wins.

An address no server opens is one no tenant may attach to, and a file whose
`listen` names one is refused when it is loaded. This is what keeps a tenant
off an address the operator did not mean to share — an admin endpoint on a
port reachable only from inside, say:

```nginx
server {
    listen 443 ssl;
    server_name _;

    tenant tenants;      # open
}

server {
    listen 8443 ssl;
    server_name admin.example.com;
                         # closed: no tenant may listen on 8443
}
```

It may be repeated to open an entry point to several zones, and at the
`http` level to open every server of the block.

Not a `location` context: a tenant is chosen while the virtual server is,
which is before a location is.

## Loading and reloading

Files are loaded at three points:

- **At startup**, before the workers are forked. A file that fails to parse
  prevents nginx from starting.
- **On a configuration reload** (`SIGHUP`). The zone is not inherited, so
  the new cycle parses every file again; the processes of the old cycle keep
  their own copy until they exit. A file that fails to parse is logged and
  the reload continues.
- **At runtime**, on `PATCH /1/control/dynamic`. Only files that changed are
  parsed; a file that fails to parse keeps the version loaded before it, and
  the other files are unaffected.

A file is considered changed when its inode or its modification time
differs. A file that no longer matches the pattern is removed from the zone
at once, and its memory is released once the last request using it is done.

Parsing happens outside the zone's write lock, so a worker never waits for
a file to be parsed.

## What a tenant may contain

A tenant is a configuration of the `http{}` level, so it may contain
`server{}` blocks, `upstream{}` blocks of its own, the `http`-level
directives that define a variable — `map`, `geo` and `split_clients` —
`log_format`, and those that declare a shared memory zone of its own:
`limit_req_zone` and `limit_conn_zone`.

Those are its own. A `log_format` it declares, an `upstream` it names, a
variable it defines belong to that tenant and collide with nothing the
operator or another tenant declares.

What it may not contain is what it could not create for itself — something
that would have to live in one process, when a tenant lives in a zone every
worker shares and arrives after the fork:

| Refused | Why |
|---|---|
| `keepalive` in an `upstream` | a connection cache belongs to one worker |
| `sticky` in an `upstream` | keeps state outside the zone |
| `resolver` in an `upstream`, `server ... resolve` | the timer that re-resolves a name is armed by a worker as it starts |
| `listen` socket options, `default_server`, `quic` | the socket already exists and belongs to the static configuration |
| `tenant_zone`, `tenant` | tenants do not nest |

A resolver, the file caches, a cache and an SSL context a tenant does not
declare either, but those it may name instead of being refused outright,
with the limits that come with sharing one; see
[Inheritance](#inheritance).

A few directives are accepted and do nothing, configuring something a
tenant is never the one to be asked about: `http2_recv_buffer_size` and the
QUIC settings of the http/3 module, which belong to a connection run with
the configuration of the default server of its address, and
`resolver_timeout` in an `upstream`, which is policy on a resolver a tenant
has none of.

### listen

A `listen` is required, and must describe an address the static
configuration already listens on, the same way it describes it:

```nginx
# static
server { listen 443 ssl; ... }

# tenant - matches
server { listen 443 ssl; ... }

# tenant - refused, that address terminates SSL
server { listen 443; ... }

# tenant - refused, the static configuration has no 127.0.0.1:443
server { listen 127.0.0.1:443; ... }
```

A tenant cannot create a listening socket, and narrowing a
wildcard address is not something it can express, so the address has to
match exactly rather than approximately.

`listen` keeps the parameters that describe the address — `ssl`, `http2`,
`quic` and `proxy_protocol` — and they have to agree with the static
configuration, which is checked. A server on an address that terminates SSL
therefore says `ssl`, and reads the way the static server on that address
does. `quic` describes a datagram socket, so an address is looked up among
the sockets of the type it asks for: the same address may be listened on
twice, once for TCP and once for QUIC, and a server saying `quic` belongs
to the second of them.

The rest is refused. A socket option such as `backlog` cannot be applied to
a socket that already exists, and `default_server` would change how the
static configuration handles an address it owns.

### server_name

At least one `server_name` is required, and names must be exact. A wildcard
or a regular expression is matched against a structure built once for all
the names of an address, which a tenant appearing on its own cannot maintain.

The static configuration wins: a tenant cannot take over a name a
static server already answers to.

## Variables

A tenant has variables of its own. Every module registers its own — `$uri`,
`$host`, `$request_method`, `$upstream_addr`, the prefix variables such as
`$http_*` and `$arg_*` — as it does for the static configuration, and a
tenant defines whatever else it needs:

```nginx
http {
    map $http_x_tenant $tenant_root {
        default      /srv/default;
        a            /srv/a;
        b            /srv/b;
    }

    server {
        listen 80;
        server_name shared.example.com;

        root $tenant_root;
    }
}
```

A variable a tenant defines is local to it. Two tenants can each define
`$tenant_root` with their own table, and neither sees the other's.

What the operator declared is not visible to a tenant either, and is not a
name a tenant may not take: a `map $x $backend` in the static configuration
and a `map $y $backend` in a tenant are two unrelated variables.

`set` works, and so do captures, named and numbered:

```nginx
http {
    server {
        listen 80;
        server_name re.example.com;

        location ~ ^/u/([^/]+)/ {
            set $user $1;
            return 200 "user=$user\n";
        }

        location ~ "^/t/(?<tenant>[a-z]+)/(?<rest>.*)$" {
            return 200 "tenant=$tenant rest=$rest\n";
        }
    }
}
```

There is no limit on how many variables a tenant may use, or on how many
captures a pattern may have, beyond what the zone holds.

A variable of a tenant is found however it is reached, whether a directive
names it at configuration time or looks it up while the request is served,
which in practice means SSI:

```nginx
map $http_x_in $mine { default TENANT; }

return 200 "$mine";                  # TENANT
# <!--# echo var="mine" -->          # TENANT
```

A name only the operator declared is found neither way, the variables of a
tenant being its own.

## Shared memory zones

A tenant may declare a shared memory zone of its own, where the module
owning it keeps the state every worker shares:

```nginx
http {
    limit_req_zone $binary_remote_addr zone=tenant:1m rate=100r/s;

    server {
        listen 8080;
        server_name a.example.com;

        location / {
            limit_req zone=tenant burst=20;
        }
    }
}
```

The zone belongs to the tenant. Another may declare one of the same name,
with its own size and its own settings, and the two are independent. A name
the static configuration declares is found first, so referring to a static
zone works as before, and declaring one over that name is refused by the
module that owns it.

Such a zone is a slab pool of its own inside the zone of the `tenant_zone`
that loaded the tenant, taken from the tenant's pool. Two things follow. It
costs its full size out of that zone, which therefore has to hold the
configuration of every tenant plus every zone they declare, and a large zone
needs that much of it contiguous. And releasing a tenant releases its zones
with everything kept in them, in one operation, which is why no module has
to free anything of its own.

The state belongs to the tenant, so it starts empty every time the tenant is
loaded: touching a file resets the counters in its zones, as reloading nginx
resets a zone it does not inherit.

A module is eligible for this if it keeps such state in the zone and nothing
outside of it, which today means `limit_req_zone` and `limit_conn_zone`. A
cache path still cannot be declared — not because of its zone, but because
the cache manager and loader walk the paths of the running cycle, which a
file loaded after the fork can never appear in.

## Upstreams

A tenant reaches a backend in either of two ways:

- **an upstream it declares**, with `server` and its parameters, a `zone` of
  its own, and any of `least_conn`, `least_time`, `ip_hash`, `hash` and
  `random`;
- **a host**, as in `proxy_pass https://nginx.org`, resolved while the
  tenant is loaded.

Both are the tenant's own: the peers are built in its pool, in the zone, so
the workers share them and the counters on them, and they go away with the
tenant. With a `zone` of its own the peers are copied into that zone
instead, by the same code that does it for a static `upstream ... zone`,
which allocates each peer by itself and locks the zone with a mutex of its
own rather than the one the tenant's memory uses. A host is resolved by a
blocking lookup in the master, the same one a static `proxy_pass
http://host` does, and the addresses stay as found until the tenant is
loaded again.

An upstream the **static** configuration declares is not one of them. It is
not visible to a tenant, and naming one is refused, so that a tenant cannot
reach a backend of the operator, or of another tenant, by guessing the name
it was given. That is also why neither way above can have cached
connections, `sticky`, runtime re-resolution or TLS towards the backend:
each of those keeps something in one process, and the static upstream that
could have supplied it is out of reach by design.

## Examples

### Per-tenant servers, added and removed at runtime

```nginx
http {
    tenant_zone tenants:16m tenants/*.conf;

    # what a tenant cannot make for itself, and may name
    resolver            10.0.0.53 valid=30s;
    open_file_cache     max=4096 inactive=60s;
    open_log_file_cache max=4096 inactive=60s;

    server {
        listen 443 ssl;
        server_name _;

        # the certificate of each tenant, by the name the client asked for
        ssl_certificate     certs/$ssl_server_name.crt;
        ssl_certificate_key certs/$ssl_server_name.key;

        tenant tenants;
        return 404;
    }
}
```

`tenants/a.conf`:

```nginx
http {
    open_log_file_cache;          # the one the operator declared

    log_format a '$remote_addr "$request" $status $upstream_addr';

    limit_req_zone $binary_remote_addr zone=perip:1m rate=100r/s;

    upstream app {
        zone app 64k;
        server 10.0.0.1:8080;
        server 10.0.0.2:8080;
    }

    server {
        listen 443 ssl;
        server_name a.example.com;

        access_log /var/log/nginx/a.log a;

        limit_req zone=perip burst=50;

        location / {
            proxy_pass http://app;
            proxy_set_header X-Tenant a;
        }
    }
}
```

The tenant names `open_log_file_cache` because it logs; it would name
`resolver` if it resolved a host at request time, and `open_file_cache` if
it served files. A tenant that names none of them simply has none.

Adding a tenant is dropping in `certs/a.example.com.crt`, writing the file
and making one API call. Everything in it — the log format, the log file,
the rate limit zone, the upstream, the routing — belongs to that tenant, and
another tenant may use the same names for its own. The static configuration
supplies the entry point, the certificate, and the three inherited caches,
and nothing else.

### A backend of the tenant's own

A tenant declares the upstream it proxies to, or names a host and lets it be
resolved while the tenant is loaded:

```nginx
http {
    upstream tenant_a {
        least_conn;
        server 10.0.1.10:8080 max_fails=2 fail_timeout=5s;
        server 10.0.1.11:8080 weight=2;
        server 10.0.1.12:8080 backup;
    }

    server {
        listen 80;
        server_name a.example.com;

        location / {
            proxy_pass http://tenant_a;
        }

        location /docs/ {
            proxy_pass            https://nginx.org/en/docs/;
            proxy_ssl_server_name on;
        }
    }
}
```

A name-based host needs `proxy_ssl_server_name on` to be sent as SNI, as it
does anywhere in nginx; that and `proxy_ssl_name` are the two `*_ssl_*`
directives a tenant may set for itself.

Both belong to this tenant: another may declare `upstream tenant_a` with
different servers, and neither sees the other's. The peers live in the zone,
so every worker balances over the same ones and the counters they keep are
shared.

Connections to such an upstream are not cached — `keepalive` needs a per
worker cache, which a configuration in a zone cannot hold. There is no way
around it: an upstream of the static configuration could cache them, but a
tenant may not name one.

### A routing table carried by the tenant

With `upstream api`, `upstream images` and `upstream web` of its own, a
tenant can carry its own table of which one to use:

```nginx
http {
    map $uri $backend {
        ~^/api/    http://api;
        ~^/img/    http://images;
        default    http://web;
    }

    server {
        listen 80;
        server_name router.example.com;

        location / {
            proxy_pass $backend;
        }
    }
}
```

The names a `proxy_pass` resolves to at runtime have to be upstreams the
tenant itself declares; what the map decides is which of them a request goes
to.

### Use cases

- **Multi-tenant hosting**, where servers are created and destroyed far more
  often than the rest of the configuration changes.
- **Control planes** that generate per-customer configuration: writing one
  file and calling the API replaces regenerating and reloading everything.
- **Large configurations** where a reload is expensive, whether because of
  the number of servers, the size of the maps, or long-lived connections
  that a reload would leave shutting down.
- **Blue/green per service**, where switching one server's backend should
  not disturb the rest.

## Module support

A module is *eligible* when it can be configured inside a tenant.
The eligible ones are:

| | |
|---|---|
| **Content and files** | core, static, index, autoindex, random index, dav, flv, mp4, empty gif, stub status |
| **Filters** | addition, copy, gunzip, gzip, gzip static, headers, image filter, range body, slice, ssi, sub |
| **Access and limits** | access, auth basic, auth request, limit conn, limit req, secure link |
| **Routing and variables** | rewrite, map, geo, split clients, referer, try files, browser, degradation, real ip, userid |
| **Upstream** | proxy, fastcgi, uwsgi, scgi, grpc, memcached, tunnel, upstream, upstream zone |
| **Balancing** | hash, ip hash, least conn, least time, random |
| **Protocols** | http/2, http/3 |
| **Other** | log, mirror |

Some of them are eligible with limits:

- **proxy, fastcgi, uwsgi, scgi, grpc, memcached, tunnel** — the backend is
  an upstream the tenant declares itself, or a host: `proxy_pass
  https://nginx.org` works, and the name is resolved while the tenant is
  loaded. An upstream of the static configuration is not available, and
  naming one is refused. A tenant connecting to a backend over
  SSL — `proxy_pass https://backend` — does so with the defaults of those
  modules: every `*_ssl_*` directive is static except `*_ssl_name` and
  `*_ssl_server_name`, which name the peer of a single connection and are
  set freely. A cache is named with `*_cache_path`, and `*_cache` resolves
  against the caches the tenant named; see [Inheritance](#inheritance).
- **upstream, upstream zone** — an `upstream` block may be declared in a
  tenant, with `server` and its parameters and a `zone` of its own.
  `keepalive`, `sticky` and `resolver` are not supported in one, and neither
  is `server ... resolve`: the timer that resolves a name is armed by a
  worker as it starts, and the upstreams of a tenant loaded later are not
  among those it arms it for. `resolver_timeout` is accepted and ignored,
  being policy on a resolver a tenant has none of.
- **log** — `access_log` may write to a file of the tenant's own, with a
  `log_format` of the tenant's own; syslog, `buffer=` and `gzip=` are not
  supported. See [Logging](#logging).
- **http/2** — `http2` in a tenant decides whether a request routed
  to it by name is served: whether a connection speaks HTTP/2 at all is
  settled from the default server of the address, in the preface check and in
  the ALPN callback, before any name is known — exactly as it is for a static
  server. Without `http2` in the tenant, an HTTP/2 request routed to
  it is answered with 421, the way nginx answers one routed to a static
  server that does not have it. `http2_recv_buffer_size` is accepted and
  ignored: the buffer is allocated by each worker from the configuration of
  the default server of the address, which a tenant is never.
- **http/3** — `http3` and `http3_hq` decide the same thing `http2` does
  above. The rest of the module configures a QUIC connection, which is run
  with the configuration of the default server of its address, before any
  name is known, so `http3_max_concurrent_streams`,
  `http3_stream_buffer_size`, `quic_retry`, `quic_gso`, `quic_host_key` and
  `quic_active_connection_id_limit` are accepted and ignored.

Not eligible:

- **ssl** — an SSL context is not pool memory, so a worker started before
  one was created cannot see it, and a tenant cannot create
  one. A tenant on an address that terminates SSL uses the context
  of the default server of that address, which covers protocols, ciphers,
  verification, the session cache and tickets. For a certificate per
  server, see below.
- **charset** — a charset is bound by its index in the module's main
  configuration, and the recode tables are indexed the same way,
  `charsets[source].tables[charset]`. Appending there from a tenant parse
  would change only the master's copy of that configuration, leaving every
  worker's index past the end of the array it forked with. The table rows are
  also sized, and the recodes a merge collected validated, in the module's
  postconfiguration, which a per-file parse does not run. Eligibility means
  copying the configuration — charsets, tables and recodes — with the indices
  kept, the way variables are copied.
- **json** — `json_set` reuses the parse tree of a source another `json_set`
  already reads, and adds to it, so a tenant naming a source the static
  configuration also names would graft nodes allocated from the pool of the
  file into the static configuration's tree, and leave it pointing there once
  the file is released. It also binds its variable to an index into its main
  configuration, which would have to be copied the way variables and
  upstreams are. Eligibility would mean giving a file a source of its own,
  and parsing the same body twice.
- **geoip**, **xslt** — these keep objects that are not pool memory, a GeoIP
  handle and parsed stylesheets, so a worker started before one was created
  cannot see it.
- **upstream keepalive** — the connections it caches are kept in the
  configuration of the upstream, which for a tenant is in a zone, so
  the workers would share a queue with no lock on it and, past that, a
  connection belonging to another process. It would take a cache per
  worker, created when a worker first uses the upstream.
- **upstream sticky** — the timer that expires its sessions lives in the
  configuration of the upstream, which for a tenant is in a zone, so
  every worker would arm and fire the same event; and the timer is armed as
  a worker starts, for the upstreams of the static configuration, which a
  file loaded later is not among. It would take the same per-worker state
  `keepalive` needs.
- **perl** — the interpreter is created while the configuration is loaded and
  belongs to the process that created it, and `perl_set` compiles a handler
  into it, so a file loaded after the workers forked could not reach theirs.

The write, header, chunked, postpone and not modified filters are on neither
list: they have no configuration and no directives of their own, so there is
nothing for eligibility to say about them. Neither is `tenant_zone`
itself: includes do not nest, and a file is loaded by the static
configuration alone.

An ineligible module is not silently ignored: its directives are refused
with `directive "..." is not supported in a tenant`. Its configuration is
still made for a tenant, holding the defaults of that module and nothing
the static configuration set, on the principle that a module configured by
nothing does nothing.

### A certificate per tenant

A tenant cannot configure a certificate, but it does not have to: the
static default server can pick one by the name the client asked for, which
[SSL](#ssl) is about.

```nginx
http {
    tenant_zone tenants:16m tenants/*.conf;

    server {
        listen 443 ssl;
        server_name _;

        ssl_certificate     certs/$ssl_server_name.crt;
        ssl_certificate_key certs/$ssl_server_name.key;

        return 404;
    }
}
```

`tenants/a.conf`:

```nginx
http {
    server {
        listen 443 ssl;
        server_name a.example.com;

        root /srv/a;
    }
}
```

A request for `a.example.com` is served the certificate at
`certs/a.example.com.crt`, and adding a tenant is dropping in a certificate
and a configuration file. The certificate is read once per worker, through
the cache of the cycle.

This does require the certificate to be findable from the name. A
`map $ssl_server_name $cert` in the static configuration works too, but has
to be changed when a tenant is added, which is a reload — so a naming
convention is what keeps the feature useful.

## Making a module eligible

A module says that its directives are allowed in a tenant:

```c
ngx_module_t  ngx_http_example_module = {
    NGX_MODULE_V1_FLAGS(NGX_HTTP_TENANT_CONF),
    ...
```

That is the whole of it for most modules. Every module has its
configurations made and its callbacks run for a tenant, whether it
advertises the flag or not, because a module that is configured by nothing
does nothing; the flag decides only whether its directives are accepted.

One flag, not one per level: where a directive is kept says nothing about
whether it can be used in a tenant, and a module advertising a level
would be advertising directives it never considered. A module with no
directives advertises nothing — unless it registers a phase handler, the
phase handlers of a tenant being its own, which is why the static module
is eligible.

A module is eligible when everything it creates while its configuration is
parsed and merged lives in the pool it is given, and everything it refers to
is either in that pool or in memory the workers already have. Concretely, it
must not, at configuration time:

- **Allocate outside the pool.** An SSL context, a GeoIP handle, a parsed
  stylesheet or a syslog peer belongs to the process that created it, and
  the master creates a tenant after the workers have forked.
- **Write into the static configuration.** The master parses a tenant
  after the workers have forked, so appending to a main configuration — an
  upstream, a charset, a log format — changes only the master's copy of it:
  a worker keeps the array it forked with, and an index into it is now out of
  range. It would also leave the static configuration pointing into the pool
  of the file, which goes away when the file is removed. Copying the
  configuration and appending to the copy is what the core and upstream
  modules do instead.
- **Keep a cache in the zone.** A cache whose contents are created by
  whichever process filled it cannot be shared, which is why
  `open_file_cache` and `open_log_file_cache` are named rather than
  declared.

A module needs no special code for a tenant. Its `create_main_conf()`,
`create_srv_conf()` and `create_loc_conf()` are called as they are for the
static configuration, its `preconfiguration()` registers the variables of
the tenant, its `init_main_conf()` finishes what the parse created, and its
`postconfiguration()` pushes its phase handlers onto arrays of the tenant's
own. The one case that needs a word is a main configuration a module cannot
make, because what it keeps there is built before the fork; it returns the
static one instead:

```c
static void *
ngx_http_example_create_main_conf(ngx_conf_t *cf)
{
    ...
    if (ngx_conf_tenant(cf)) {
        return ngx_http_conf_get_module_static_main_conf(cf,
                                                  ngx_http_example_module);
    }
    ...
```

What a parse did not create it does not initialize either, so such a module
needs nothing in `init_main_conf()`: initializing the static configuration
a second time, into the pool of the tenant, would leave it pointing there
once the tenant is released.

A module that is eligible except for a few directives refuses those from
the handler or the merge that would make what they configure, which is
where the reason for refusing is:

```c
    if (ngx_conf_tenant(cf)) {
        return "is not supported in a tenant";
    }
```

The message names the directive, the file and the line, and can say what to
write instead or what the static configuration is missing. Where several
directives configure one thing, the merge says it once for all of them:
this is how the upstream modules refuse their SSL settings, there being no
`SSL_CTX` a tenant could be given.

And where the thing itself can be handed over, the directive takes no
parameters at all and fetches it with
`ngx_http_conf_get_module_static_*_conf()` — which is what `resolver`,
`open_file_cache` and `open_log_file_cache` do. Every use of that macro is
a place where the static configuration decides something for every tenant.

Referring to what the static configuration declares is fine, and is how an
open file and a temporary path are used: the lookup finds the static entry,
which predates the fork. Creating a new one is refused where it happens,
naming what is missing.

A shared memory zone is the exception: a module eligible at the `http` level
may declare one, which is created inside the zone of the file and released
with it. What the module keeps there must be reachable from its
configuration and nothing else — a pointer held in process memory, a timer
or a descriptor makes it ineligible, whatever the zone holds.

Adding a variable, compiling a regular expression, and opening a file are
all handled centrally, so a module needs no special code for them.

## Implementation notes

- **Pools in shared memory.** `ngx_create_shared_pool()` returns an
  `ngx_pool_t` backed by a slab pool, so the existing `ngx_palloc()` API
  puts a whole parsed configuration into a zone. Releasing a file is
  destroying its pool.

- **A copy of the cycle.** A file is parsed against a copy of the running
  cycle, so that a directive registering a path, an open file or a zone
  finds the one the static configuration declares rather than adding to the
  running cycle. Creating a new one is refused at the point of creation.

- **A configuration in its own right.** A tenant file holds an `http{}`
  block, parsed at a level of its own so that nothing may appear beside it.
  Every level of that configuration is made by the modules themselves, as
  `ngx_http_block()` has them make the static one: the `http{}` level of the
  tenant is merged with itself, which turns the placeholders of every module
  into its defaults, and the servers of the tenant are merged against it.
  So nothing an operator wrote for their own servers reaches a tenant.

- **Every module, eligible or not.** A module has its configurations made
  and its callbacks run for a tenant whether it advertises the flag or not,
  because a module that is configured by nothing does nothing. Eligibility
  is asked of a directive, in `ngx_conf_handler()`, and nowhere else. So the
  variables, the phase handlers, the log formats and the hashes a name is
  looked up in are all the tenant's own.

- **What a tenant names, and how.** Some things a tenant cannot make, the
  default being to create something that belongs to one process. Those
  directives take no parameters and fetch the object with
  `ngx_http_conf_get_module_static_*_conf()`, which reads `cf->static_ctx`,
  the static `http{}` level: `resolver` and `open_file_cache` of the core
  module, and `open_log_file_cache` of the log module. A cache is named by
  the name of its zone instead, which `ngx_shared_memory_add()` finds
  through the copied cycle. Every one of these is a place where the static
  configuration decides something for a tenant; see
  [Inheritance](#inheritance).

  For a directive to take no parameters as well as some, it declares
  `NGX_CONF_NOARGS` alongside its `NGX_CONF_1MORE` or `NGX_CONF_TAKE`
  flags. The argument count check used to refuse that combination, testing
  `NGX_CONF_1MORE` and `NGX_CONF_2MORE` before the table `NGX_CONF_NOARGS`
  is read from; it now takes the no-argument case first. No directive of
  nginx combined them before, so nothing else changes.

- **A configuration of the tenant's own.** A tenant has its own main
  configuration, which is where what belongs to the tenant rather than to a
  server is kept — its servers, its variables, its log formats, its
  upstreams. Choosing a virtual server now takes the main configuration with
  it, as choosing one for a subrequest already did, and a request switching
  into a tenant or back out of one starts the variables of the
  configuration it arrives in afresh: an index means nothing outside the
  configuration that assigned it.

- **The filters of the process.** These are chained by the
  `postconfiguration()` of every module, and every pass builds the same
  chain, so a tenant rebuilding it changes nothing. The chain is kept before
  a tenant is parsed and put back once it is done with, so that a tenant
  failing to load leaves none of it half built.

- **Entry points are opened, not found.** `tenant` keeps an array of zones
  on the server configuration, and a lookup searches only those. A tenant is
  checked against the same array when it is loaded, through the default
  server of the address its `listen` resolved to, so an address no entry
  point opened is refused there rather than silently never matching.

- **What a tenant costs.** A tenant holds the server and location
  configuration of every module, its variables and the hashes they are
  looked up in, the phase arrays and the engine built from them, and
  whatever its own directives allocate. Nothing is shared with the static
  configuration but the three inherited objects above, which is what makes a
  tenant independent of it; the price is that each tenant pays for its own
  copy of what every module keeps.

- **The name index.** Each address the tenants listen on has a tree
  of names in the zone, pointing at the server and the file it came from. A
  lookup takes a reference to that file under a read lock and holds it until
  the request is done, so a file removed mid-request stays valid.

- **Peers in the zone.** An upstream a tenant adds has its peers built
  in the pool of the file, so they are in the zone and every worker uses the
  same ones. The round robin code locks peers when they have a slab pool of
  their own, which is how an upstream with a `zone` works, so the file's
  upstreams are given the pool of their zone and are locked the same way.
  What such an upstream has no need of is the rest of the zone module: its
  peers never change, so nothing tracks a generation.

- **Zones are not inherited.** What is loaded into a zone refers to the
  static configuration of the cycle that parsed it, so the zone is marked
  `noreuse`: a new cycle maps a new zone and loads everything again, while
  the processes of the old cycle keep their own mapping until they exit.

- **No SSL context is ever created.** A tenant uses the one the static
  configuration created before the fork, that of the default server of its
  address. Every `ngx_ssl_create()` call site in http is unreachable from a
  tenant parse, which is what keeps the session cache, the tickets and
  everything else a context owns working. Towards a backend there is none to
  inherit, since a tenant has no static upstream, so those directives are
  refused outright.

- **Logs go through a cache, not a descriptor.** A descriptor of the cycle
  is opened before the fork, which a tenant arrives too late for, so
  `access_log` in a tenant compiles its name as a script even when the name
  has no variables in it, and writes through `ngx_open_cached_file()` — the
  path a static `access_log` with a variable in its name already takes. The
  cache is the inherited one, so each worker holds its own descriptors.

## Limitations

- A tenant cannot create a listening socket, so its `listen` must match a
  static one exactly, including `ssl`, `http2` and `proxy_protocol`. Socket
  options, `default_server` and `quic` are refused. The address must also be
  one an entry point opened to its zone with `tenant`.
- `server_name` must be exact. No wildcards, no regular expressions.
- A temporary path must be declared statically. A shared memory zone a
  tenant may declare for itself, if the module owning it is eligible at the
  `http` level. A log file it may name freely.
- `resolver`, `open_file_cache` and `open_log_file_cache` cannot be created
  in a tenant; a tenant names the one the static configuration made by
  writing the directive with no parameters, or has none. A cache path
  cannot be declared at all.
- A tenant has no access to the upstreams of the static configuration, and
  naming one is refused.
- An upstream a tenant declares cannot cache connections: `keepalive` is not
  supported in one. Nor can it re-resolve a name while running; the
  addresses are those found when the tenant was loaded, and reloading it is
  what resolves them again.
- Resolving a host while loading a tenant is a blocking lookup in the
  master, the same one a static `proxy_pass http://host` does.
- A regular expression in a tenant is not JIT-compiled: JIT output is mapped
  executable memory outside the pool, so the workers could not see it.
  Static patterns are unaffected.
- A tenant configures no SSL, towards a client or a backend, beyond
  `*_ssl_name` and `*_ssl_server_name`; see [SSL](#ssl).
- Two tenants naming the same cache share its entries, and a tenant cannot
  declare one of its own; see [The http cache](#the-http-cache).
- The operator's `access_log`, `add_header` and the rest do not apply to a
  request a tenant serves: the tenant's configuration replaces theirs
  entirely. A tenant with no `access_log` is not logged. `$tenant` is not
  available yet, so attributing a request to a tenant in a static log is not
  possible either.
- Change detection uses the modification time, which has a resolution of one
  second, so two writes to the same file within the same second look like
  one. A tool that rewrites files quickly should account for this.

## Diagnostics

Every refusal names what is missing or what to do about it:

| Message | Meaning |
|---|---|
| `directive "..." is not supported in a tenant` | the module is not eligible, or the directive is marked static |
| `"..." directive is not supported in a tenant` | the directive is refused by its own handler |
| `"resolver" directive cannot be created in a tenant, only named with no address` | write `resolver;` |
| `"open_file_cache" directive cannot be created in a tenant, only named with no parameters` | write `open_file_cache;` |
| `"resolver" directive is not declared by the static configuration` | named with nothing to name |
| `"resolver" directive requires an address outside a tenant` | the bare form in the static configuration |
| `"listen ..." does not match any address the static configuration listens on` | no static `listen` for that exact address |
| `"..." is not supported in a tenant, where "listen" takes only the parameters describing the address` | a socket option or `default_server` |
| `"listen ..." differs from the static configuration in "ssl"` | the address terminates SSL and the tenant `listen` does not say so, or the other way round |
| `wildcard and regular expression server names are not supported in a tenant` | only an exact `server_name` |
| `no "listen" in a server defined in "..."` / `no "server_name" in "..."` | a server that nothing could reach |
| `no "http" block in "..."` | a tenant file holds one `http{}` block |
| `"..." is not allowed here` | a directive beside that block rather than inside it |
| `"listen ..." names an address not open to the tenant zone "..."` | no entry point on that address named this zone with `tenant` |
| `unknown tenant zone "..."` | `tenant` names a zone no `tenant_zone` declared |
| `upstream "..." is not defined in the static configuration` | built without the upstream zone module, which is what locks the peers |
| `duplicate upstream "..."` | a name this tenant already declares |
| `resolving names at run time is not supported in a tenant in upstream "..."` | `server ... resolve` |
| `zero size shared memory zone "..."` | a zone referred to and never declared |
| `the shared memory zone "..." is too small` | less than two pages, which a slab pool cannot work in |
| `the path "..." is not declared in the static configuration` | a temporary or cache path |
| `a listening socket cannot be created in a tenant` | a `listen` on an address the static configuration does not have |
| `unknown "..." variable` | a name the tenant does not define |
| `the duplicate "..." variable` | a `map` or `set` redefining a variable that is not changeable |

A runtime load returns them in the API response:

```
$ curl -X PATCH http://127.0.0.1:8081/1/control/dynamic
{"logs":["2026/09/10 12:00:00 [emerg] 1234#0: directive \"keepalive\" is not supported in a tenant in /etc/nginx/servers/a.conf:3\n"]}
```

---

For nginx itself, see the [nginx documentation](https://nginx.org/en/docs/).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="logo/nginx-multitenant-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="logo/nginx-multitenant.svg">
  <img alt="NGINX Multitenant" src="logo/nginx-multitenant.svg">
</picture>

This branch adds `server{}` configurations that are loaded from separate
files into shared memory, and can be added, changed and removed at runtime
without reloading nginx and without respawning workers.

A reload replaces the whole configuration and restarts the workers, which is
cheap when it happens rarely and expensive when a server is added every few
seconds. A dynamic server is parsed by the master process into a shared
memory zone, where the workers see it immediately, so adding one costs a
parse of one file instead of a reload of everything.

## Contents

- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Directives](#directives)
- [Loading and reloading](#loading-and-reloading)
- [What a dynamic file may contain](#what-a-dynamic-file-may-contain)
- [Variables](#variables)
- [Shared memory zones](#shared-memory-zones)
- [Upstreams](#upstreams)
- [Examples](#examples)
- [Module support](#module-support)
- [Making a module eligible](#making-a-module-eligible)
- [Implementation notes](#implementation-notes)
- [Limitations](#limitations)
- [Diagnostics](#diagnostics)

## How it works

The static configuration declares a pattern of files and a zone to load them
into:

```nginx
http {
    dynamic_include zone=servers:4m /etc/nginx/servers/*.conf;
}
```

Each matching file is parsed in the context of the static `http{}` block into
its own pool inside that zone. The servers it defines are indexed by the
address they listen on and their name, and a request whose `Host` matches
none of the static server names of its address is looked up in that index.

A dynamic server is not a separate nginx configuration. It inherits the
static `http{}` level for everything it does not configure itself, and it
refers to what the static configuration declares — log files, temporary
paths — rather than creating its own. Variables, upstreams and shared memory
zones it may add for itself, and those belong to its file alone.

## Quick start

```nginx
http {
    dynamic_include zone=servers:4m servers/*.conf;

    server {
        listen 80;
        server_name _;
        return 404;
    }
}
```

`servers/tenant-a.conf`:

```nginx
server {
    listen 80;
    server_name a.example.com;

    root /srv/a;
}
```

Start nginx with a control socket, and reload the dynamic part after
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

### dynamic_include

**Syntax:** `dynamic_include zone=name:size pattern;`
**Context:** `http`

Loads every file matching `pattern` into the shared memory zone `name`.
`pattern` is a glob, resolved relative to the prefix if it is not absolute.
The zone must be at least eight pages, and holds every configuration loaded
through this directive, so it has to be sized for the total.

The directive may appear more than once, each time with its own zone:

```nginx
dynamic_include zone=tenants:16m tenants/*.conf;
dynamic_include zone=internal:1m internal/*.conf;
```

Servers are looked up in the order the directives appear. If two patterns
match the same file, it is loaded into both zones, and only the entry from
the first directive is ever found.

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

## What a dynamic file may contain

A dynamic file is parsed in the context of the static `http{}` block, so it
may contain `server{}` blocks, those `http`-level directives that define a
variable — `map`, `geo` and `split_clients` — and those that declare a
shared memory zone of the file's own: `limit_req_zone` and
`limit_conn_zone`.

It may not contain the `http`-level directives that create something the
static configuration owns, whether because the workers could not see it or
because it would outlive the file:

| Refused | Use instead |
|---|---|
| `log_format` | a format the static configuration declares, by name |
| `proxy_cache_path` and the other `*_cache_path` | a zone and path the static configuration declares |
| `resolver` | configure it statically; it is inherited |
| `keepalive` in an `upstream` | an upstream of the static configuration, which may cache connections |
| `sticky` in an `upstream` | an upstream of the static configuration |
| `dynamic_include` | includes do not nest |

An `http`-level directive that only sets a value, such as
`variables_hash_max_size`, is refused as a duplicate, since the static
configuration has already settled it. A handler without a duplicate check
may accept one and have no effect: `degradation` is the one such case, and
what it sets is invisible to the workers.

### listen

A `listen` is required, and must describe an address the static
configuration already listens on, the same way it describes it:

```nginx
# static
server { listen 443 ssl; ... }

# dynamic - matches
server { listen 443 ssl; ... }

# dynamic - refused, that address terminates SSL
server { listen 443; ... }

# dynamic - refused, the static configuration has no 127.0.0.1:443
server { listen 127.0.0.1:443; ... }
```

A dynamic configuration cannot create a listening socket, and narrowing a
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
the names of an address, which a file appearing on its own cannot maintain.

The static configuration wins: a dynamic server cannot take over a name a
static server already answers to.

## Variables

A dynamic file may use any variable the static configuration defines, and
may define variables of its own:

```nginx
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
```

A variable defined in a file is local to that file. Two files can each
define `$tenant_root` with their own table, and neither sees the other's.

`set` works, and so do captures, named and numbered:

```nginx
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
```

There is no limit on how many variables a file may use, or on how many
captures a pattern may have, beyond what the zone holds.

One thing a file-local variable cannot do is be looked up by name while a
request is served. That happens only where a directive names a variable at
that point rather than at configuration time, which in practice means SSI:

```nginx
# refers to the variable, and works
return 200 "$file_local";

# names it while serving, and does not find a file-local one
# <!--# echo var="file_local" -->
```

A name the static configuration defines is found either way, whether it is
indexed there or not, and so are the prefix variables such as `$http_*` and
`$arg_*`. The reason a file-local one is not is memory: the hash those
lookups use would be the largest thing a file keeps, and almost all of it
would be a copy of what the static configuration already has, so a file
keeps none and inherits the static one.

That inherited hash holds the static definitions, so a file that shadows a
changeable static variable sees its own value everywhere except in such a
lookup, which sees the static one:

```nginx
map $http_x_in $shadowed { default FILE-version; }   # shadows a static map

return 200 "$shadowed";                  # FILE-version
# <!--# echo var="shadowed" -->          # STATIC-version
```

Shadow a name only where nothing looks it up by name at runtime.

## Shared memory zones

A dynamic file may declare a shared memory zone of its own, where the module
owning it keeps the state every worker shares:

```nginx
limit_req_zone $binary_remote_addr zone=tenant:1m rate=100r/s;

server {
    listen 8080;
    server_name a.example.com;

    location / {
        limit_req zone=tenant burst=20;
    }
}
```

The zone belongs to the file. Another file may declare one of the same name,
with its own size and its own settings, and the two are independent. A name
the static configuration declares is found first, so referring to a static
zone works as before, and declaring one over that name is refused by the
module that owns it.

Such a zone is a slab pool of its own inside the zone of the
`dynamic_include` that loaded the file, taken from the pool of the file. Two
things follow. It costs its full size out of that zone, which therefore has
to hold the configurations of every file plus every zone they declare, and a
large zone needs that much of it contiguous. And releasing a file releases
its zones with everything kept in them, in one operation, which is why no
module has to free anything of its own.

The state belongs to the file, so it starts empty every time the file is
loaded: touching a file resets the counters in its zones, as reloading nginx
resets a zone it does not inherit.

A module is eligible for this if it keeps such state in the zone and nothing
outside of it, which today means `limit_req_zone` and `limit_conn_zone`. A
cache path still cannot be declared — not because of its zone, but because
the cache manager and loader walk the paths of the running cycle, which a
file loaded after the fork can never appear in.

## Upstreams

A dynamic file reaches a backend in any of three ways:

- **an upstream of the static configuration**, by name, which is the only
  way to get cached connections, `sticky` or runtime re-resolution;
- **an upstream the file declares**, with `server` and its parameters, a
  `zone` of its own, and any of `least_conn`, `least_time`, `ip_hash`,
  `hash` and `random`;
- **a host**, as in `proxy_pass https://nginx.org`, resolved while the file
  is loaded.

The last two are the file's own: the peers are built in its pool, in the
zone, so the workers share them and the counters on them, and they go away
with the file. With a `zone` of its own the peers are copied into that zone
instead, by the same code that does it for a static `upstream ... zone`,
which allocates each peer by itself and locks the zone with a mutex of its
own rather than the one the file's memory uses. A host is resolved by a
blocking lookup in the master, the same one a static `proxy_pass
http://host` does, and the addresses stay as found until the file is loaded
again.

## Examples

### Per-tenant servers, added and removed at runtime

```nginx
http {
    dynamic_include zone=tenants:16m tenants/*.conf;

    upstream app { server 10.0.0.1:8080; server 10.0.0.2:8080; }

    limit_req_zone $binary_remote_addr zone=perip:10m rate=100r/s;
    proxy_cache_path /var/cache/nginx keys_zone=cache:10m levels=1:2;
    log_format tenant '$remote_addr "$request" $status $host';

    server {
        listen 443 ssl;
        server_name _;

        # the certificate of each tenant, by the name the client asked for
        ssl_certificate     certs/$ssl_server_name.crt;
        ssl_certificate_key certs/$ssl_server_name.key;

        access_log /var/log/nginx/tenants.log tenant;
        return 404;
    }
}
```

`tenants/a.conf`:

```nginx
server {
    listen 443 ssl;
    server_name a.example.com;

    access_log /var/log/nginx/tenants.log tenant;

    limit_req zone=perip burst=50;

    location / {
        proxy_pass http://app;
        proxy_cache cache;
        proxy_cache_valid 200 1m;
        proxy_set_header X-Tenant a;
    }
}
```

Adding a tenant is dropping in `certs/a.example.com.crt`, writing the file
and making one API call. The upstream, the rate limit zone, the cache, the
log file and the SSL configuration all come from the static configuration;
the rate limit, the headers and the routing are the file's own.

### A backend of the file's own

A file may declare the upstream it proxies to, or name a host and let it be
resolved while the file is loaded:

```nginx
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
```

A name-based host needs `proxy_ssl_server_name on` to be sent as SNI, as it
does anywhere in nginx; that and `proxy_ssl_name` are the two `*_ssl_*`
directives a dynamic file may set for itself.

Both belong to this file: another file may declare `upstream tenant_a` with
different servers, and neither sees the other's. The peers live in the zone,
so every worker balances over the same ones and the counters they keep are
shared.

Connections to such an upstream are not cached — `keepalive` needs a per
worker cache, which a configuration in a zone cannot hold. An upstream of
the static configuration can cache them, and a dynamic file may name it.

### A routing table carried by the file

With `upstream api`, `upstream images` and `upstream web` declared
statically, a file can carry its own table of which one to use:

```nginx
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
```

The names a `proxy_pass` resolves to at runtime have to be upstreams the
static configuration declares or the file itself does; what the file decides
is which of them a request goes to.

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

A module is *eligible* when it can be configured inside a dynamic server.
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

- **proxy, fastcgi, uwsgi, scgi, grpc, memcached, tunnel** — the backend may
  be an upstream of the static configuration, one the file declares itself,
  or a host: `proxy_pass https://nginx.org` works, and the name is resolved
  while the file is loaded. A dynamic file connecting to a backend over
  SSL — `proxy_pass https://backend` — does so with the settings of the
  enclosing static configuration: every `*_ssl_*` directive is static except
  `*_ssl_name` and `*_ssl_server_name`, which name the peer of a single
  connection and are set freely.
- **upstream, upstream zone** — an `upstream` block may be declared in a
  dynamic file, with `server` and its parameters and a `zone` of its own.
  `keepalive`, `sticky`, `resolver` and `resolver_timeout` are not supported
  in one, and neither is `server ... resolve`: the timer that resolves a name
  is armed by a worker as it starts, and the upstreams of a file loaded later
  are not among those it arms it for.
- **log** — `access_log` may write to a file the static configuration opens,
  with a `log_format` it declares. Declaring a format, logging to syslog,
  `open_log_file_cache` and creating a buffer for a file are not supported.
- **http/2** — `http2` in a dynamic server decides whether a request routed
  to it by name is served: whether a connection speaks HTTP/2 at all is
  settled from the default server of the address, in the preface check and in
  the ALPN callback, before any name is known — exactly as it is for a static
  server. Without `http2` in the dynamic server, an HTTP/2 request routed to
  it is answered with 421, the way nginx answers one routed to a static
  server that does not have it. `http2_recv_buffer_size` is not supported: the
  buffer is allocated by each worker from the configuration it was started
  with.
- **http/3** — `http3` and `http3_hq` decide the same thing `http2` does
  above. The rest of the module configures a QUIC connection, which is run
  with the configuration of the default server of its address, before any
  name is known, so `http3_max_concurrent_streams`,
  `http3_stream_buffer_size`, `quic_retry`, `quic_gso`, `quic_host_key` and
  `quic_active_connection_id_limit` are not supported.

Not eligible:

- **ssl** — an SSL context is not pool memory, so a worker started before
  one was created cannot see it, and a dynamic configuration cannot create
  one. A dynamic server on an address that terminates SSL uses the context
  of the default server of that address, which covers protocols, ciphers,
  verification, the session cache and tickets. For a certificate per
  server, see below.
- **charset** — a charset is bound by its index in the module's main
  configuration, and the recode tables are indexed the same way,
  `charsets[source].tables[charset]`. Appending there from a dynamic parse
  would change only the master's copy of that configuration, leaving every
  worker's index past the end of the array it forked with. The table rows are
  also sized, and the recodes a merge collected validated, in the module's
  postconfiguration, which a per-file parse does not run. Eligibility means
  copying the configuration — charsets, tables and recodes — with the indices
  kept, the way variables are copied.
- **json** — `json_set` reuses the parse tree of a source another `json_set`
  already reads, and adds to it, so a dynamic file naming a source the static
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
  configuration of the upstream, which for a dynamic file is in a zone, so
  the workers would share a queue with no lock on it and, past that, a
  connection belonging to another process. It would take a cache per
  worker, created when a worker first uses the upstream.
- **upstream sticky** — the timer that expires its sessions lives in the
  configuration of the upstream, which for a dynamic file is in a zone, so
  every worker would arm and fire the same event; and the timer is armed as
  a worker starts, for the upstreams of the static configuration, which a
  file loaded later is not among. It would take the same per-worker state
  `keepalive` needs.
- **perl** — the interpreter is created while the configuration is loaded and
  belongs to the process that created it, and `perl_set` compiles a handler
  into it, so a file loaded after the workers forked could not reach theirs.

The write, header, chunked, postpone and not modified filters are on neither
list: they have no configuration and no directives of their own, so there is
nothing for eligibility to say about them. Neither is `dynamic_include`
itself: includes do not nest, and a file is loaded by the static
configuration alone.

An ineligible module is not silently ignored: its directives are refused
with `directive "..." is not supported in a dynamic configuration`, and a
dynamic server uses the configuration of the static `http{}` level for it.

### A certificate per dynamic server

A dynamic server cannot configure a certificate, but it does not have to:
the static default server can pick one by the name the client asked for.

```nginx
http {
    dynamic_include zone=tenants:16m tenants/*.conf;

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
server {
    listen 443 ssl;
    server_name a.example.com;

    root /srv/a;
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

A module says that a dynamic configuration may make the configurations it
keeps, rather than inheriting those of the static level around it, and that
its directives are allowed there:

```c
ngx_module_t  ngx_http_example_module = {
    NGX_MODULE_V1_FLAGS(NGX_HTTP_DYN_CONF),
    ...
```

One flag, not one per level: where a directive is kept says nothing about
whether it can be used in a dynamic file, and a module advertising a level
would be advertising directives it never considered. A module with nothing
of its own, and no directive, advertises nothing.

A module is eligible when everything it creates while its configuration is
parsed and merged lives in the pool it is given, and everything it refers to
is either in that pool or in memory the workers already have. Concretely, it
must not, at configuration time:

- **Allocate outside the pool.** An SSL context, a GeoIP handle, a parsed
  stylesheet or a syslog peer belongs to the process that created it, and
  the master creates a dynamic configuration after the workers have forked.
- **Write into the static configuration.** The master parses a dynamic file
  after the workers have forked, so appending to a main configuration — an
  upstream, a charset, a log format — changes only the master's copy of it:
  a worker keeps the array it forked with, and an index into it is now out of
  range. It would also leave the static configuration pointing into the pool
  of the file, which goes away when the file is removed. Copying the
  configuration and appending to the copy is what the core and upstream
  modules do instead.
- **Keep a cache in the zone.** A cache whose contents are created by
  whichever process filled it cannot be shared, which is why
  `open_log_file_cache` is refused.

What a module makes of its main configuration is its own decision. One that
keeps something a dynamic file may add to makes a new one from the static
one:

```c
static void *
ngx_http_example_create_main_conf(ngx_conf_t *cf)
{
    ...
    if (cf->dynamic) {
        prev = ngx_http_conf_get_module_main_conf(cf, ngx_http_example_module);

        *emcf = *prev;                  /* what the static one settled */
        ... copy what the file appends to, into cf->pool ...

        return emcf;
    }
    ...
```

Its `init_main_conf()` is then called once the file is parsed, as it is for
the static configuration, and has to finish only what the file added.

A module keeping nothing a file adds to returns the one it was given
instead, which is how the caches of `proxy_cache_path` and the formats of
`log_format` are still found:

```c
static void *
ngx_http_example_create_main_conf(ngx_conf_t *cf)
{
    ...
    if (cf->dynamic) {
        return ngx_http_conf_get_module_main_conf(cf, ngx_http_example_module);
    }
    ...
```

What a parse did not create it does not initialize either, so such a module
needs nothing in `init_main_conf()`: initializing the static configuration
a second time, into the pool of the file, would leave it pointing there once
the file is released.

A module that is eligible except for a few such directives marks those
`NGX_STATIC_CONF` instead of giving up eligibility altogether:

```c
    { ngx_string("example_ssl_ciphers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_STATIC_CONF
                        |NGX_CONF_TAKE1,
```

Such a directive is refused in a dynamic file, naming the file and the line,
and is inherited from the enclosing static level instead. This is how the
upstream modules keep their SSL settings, and the log module its
`log_format`, static.

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

- **The `http{}` level is a complete configuration.** It used to be only a
  merge parent, holding the placeholders a merge turns into defaults, so it
  is merged with itself once while the static configuration loads. That
  makes it what a server with no directives at all would get, which is what
  a dynamic server starts from, and means nothing has to be created in a
  dynamic server's pool that outlives it.

- **Inheritance for ineligible modules.** A dynamic server's configuration
  for a module it may not configure is the `http{}` level's, by pointer.
  Merging skips those modules, since their configuration is already merged.

- **A configuration of the file's own.** The file has its own main
  configuration for the core module, which is where what belongs to the
  file rather than to a server is kept. Choosing a virtual server now takes
  the main configuration with it, as choosing one for a subrequest already
  did.

- **Copy and append.** A file extends an array of the main configuration by
  copying the static elements into its own pool and appending its own. The
  static prefix keeps its indexes, so an index or a pointer into it held by
  a configuration the file inherits stays valid, while what the file adds
  exists only for that file. This is how variables work: a request switching
  to a dynamic server grows its array of values to fit, keeping the ones
  already set. A definition is copied rather than shared, because indexing
  one writes the index back into it, and an index means nothing outside the
  file that assigned it.

- **What a file does not keep.** The copies a file makes to resolve its
  variables against, and the hash a name is looked up in while a request is
  served, are the largest part of what copy and append would cost. Neither
  outlives the parse: what a request needs of a definition is in the
  variable by then, and the inherited hash answers for every name the static
  configuration defines. Dropping both took a file of one server and one
  location from about 52k of zone to about 37k, so a 1m zone holds 28 of
  them rather than 20. What remains is mostly the server and location
  configuration of every eligible module, which is what a dynamic server
  is.

- **The name index.** Each address the dynamic servers listen on has a tree
  of names in the zone, pointing at the server and the file it came from. A
  lookup takes a reference to that file under a read lock and holds it until
  the request is done, so a file removed mid-request stays valid.

- **Peers in the zone.** An upstream a dynamic file adds has its peers built
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

- **No SSL context is ever created.** A dynamic configuration uses one the
  static configuration created before the fork: the default server's on the
  server side, the http{} level's on the upstream side. Every
  `ngx_ssl_create()` call site in http is unreachable from a dynamic parse,
  which is what keeps the session cache, the tickets and everything else a
  context owns working.

## Limitations

- A dynamic server cannot create a listening socket, so its `listen` must
  match a static one exactly, including `ssl`, `http2` and
  `proxy_protocol`. Socket options, `default_server` and `quic` are refused.
- `server_name` must be exact. No wildcards, no regular expressions.
- An open file and a temporary path must be declared statically; a dynamic
  file refers to them. A shared memory zone it may declare for itself, if the
  module owning it is eligible at the `http` level.
- `resolver` is not supported.
- A dynamic file cannot contain `log_format`, `open_log_file_cache`, a cache
  path, `resolver` or `dynamic_include`. It refers to what the static
  configuration declares instead.
- An upstream a dynamic file declares cannot cache connections: `keepalive`
  is not supported in one. Nor can it re-resolve a name while running; the
  addresses are those found when the file was loaded, and reloading the file
  is what resolves them again.
- Resolving a host while loading a file is a blocking lookup in the master,
  the same one a static `proxy_pass http://host` does.
- A regular expression in a dynamic file is not JIT-compiled: JIT output is
  mapped executable memory outside the pool, so the workers could not see
  it. Static patterns are unaffected.
- A dynamic server cannot configure SSL at all. It uses the context of the
  default server of its address; a certificate per server is done with
  `ssl_certificate certs/$ssl_server_name.crt` on that default server.
- Nor can it configure SSL towards a backend, beyond `*_ssl_name` and
  `*_ssl_server_name`: every other `*_ssl_*` directive of the upstream
  modules is static. A dynamic file may still `proxy_pass https://backend`,
  with the settings of the enclosing static configuration.
- Change detection uses the modification time, which has a resolution of one
  second, so two writes to the same file within the same second look like
  one. A tool that rewrites files quickly should account for this.

## Diagnostics

Every refusal names what is missing or what to do about it:

| Message | Meaning |
|---|---|
| `directive "..." is not supported in a dynamic configuration` | the module is not eligible |
| `"listen ..." does not match any address the static configuration listens on` | no static `listen` for that exact address |
| `"..." is not supported in a dynamic configuration, where "listen" takes only the parameters describing the address` | a socket option or `default_server` |
| `"listen ..." differs from the static configuration in "ssl"` | the address terminates SSL and the dynamic `listen` does not say so, or the other way round |
| `only an exact server name is supported in a dynamic configuration` | a wildcard or regular expression name |
| `no "listen" in a server defined in "..."` / `no "server_name" in "..."` | a server that nothing could reach |
| `upstream "..." is not defined in the static configuration` | built without the upstream zone module, which is what locks the peers |
| `duplicate upstream "..."` | a name the static configuration, or the file, already declares |
| `zero size shared memory zone "..."` | a zone referred to and never declared |
| `the shared memory zone "..." is too small` | less than two pages, which a slab pool cannot work in |
| `"..." is not a file the static configuration opens` | a log file the static configuration does not open |
| `the path "..." is not declared in the static configuration` | a temporary or cache path |
| `"log_format" directive is not supported in a dynamic configuration` | declare the format statically and refer to it by name |
| `"..." directive is duplicate` | an `http`-level value the static configuration has already settled |
| `unknown "..." variable` | a name neither the static configuration nor the file defines |
| `the duplicate "..." variable` | a `map` or `set` redefining a variable that is not changeable |

A runtime load returns them in the API response:

```
$ curl -X PATCH http://127.0.0.1:8081/1/control/dynamic
{"logs":["2026/09/10 12:00:00 [emerg] 1234#0: directive \"keepalive\" is not supported in a dynamic configuration in /etc/nginx/servers/a.conf:3\n"]}
```

---

For nginx itself, see the [nginx documentation](https://nginx.org/en/docs/).

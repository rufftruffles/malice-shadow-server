# malice/shadow-server

Malice plugin for [ShadowServer](https://shadowserver.org/) hash lookups.

The engine queries ShadowServer for a file's MD5/SHA1 hash and records the
result in Elasticsearch under `plugins.intel.shadow-server`. No API key is
required.

## Endpoints (verified 2026-09-04)

bin-test (live): `http://bin-test.shadowserver.org/api?md5=<hash>` (or
`?sha1=<hash>`). Tests the hash against ShadowServer's list of known software
applications. A no-match returns `<hash>\n`; a match returns `<hash> {json}\n`.

sandbox (legacy, dead): `http://innocuous.shadowserver.org/api/?query=<hash>`.
As of 2026-09-04 this endpoint is NXDOMAIN. The lookup is still attempted and
any failure is recorded gracefully (`sandbox.error`); it never crashes the scan.

## Usage

```
docker run --rm -e MALICE_SCANID=<id> -e MALICE_ELASTICSEARCH_URL=http://172.17.0.1:9200 \
  malice/shadow-server:latest lookup <md5-or-sha1>
```

## Build

```
make build && make tag
```

## License

Apache 2.0

####################################################
# GOLANG BUILDER
####################################################
FROM golang:1.25-bookworm AS go_builder

# Local ES 8 port of malice-plugins/pkgs. Passed as an additional build
# context: docker build --build-context pkgs=../malice-plugins
COPY --from=pkgs . /build/malice-plugins/
COPY . /build/shadow-server/
WORKDIR /build/shadow-server

# Pure Go (stdlib net/http only) -> static binary so it runs on the
# musl-based runtime below.
RUN CGO_ENABLED=0 go build -buildvcs=false -ldflags "-s -w -X main.Version=v$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/lookup .

####################################################
# SHADOW-SERVER RUNTIME
####################################################
FROM alpine:3.22

LABEL maintainer="https://github.com/blacktop"

LABEL malice.plugin.repository="https://github.com/malice-plugins/shadow-server.git"
LABEL malice.plugin.category="intel"
LABEL malice.plugin.mime="hash"
LABEL malice.plugin.docker.engine="*"

# /malware is the read-only sample mount point (malice volume -> /malware:ro).
# The lookup is hash-based and never reads the sample, but the core mounts it
# regardless, so the path must exist.
RUN apk add --no-cache ca-certificates su-exec \
  && addgroup -S malice \
  && adduser -S -G malice -s /bin/sh malice \
  && mkdir -p /malware \
  && chown -R malice:malice /malware

COPY --from=go_builder /bin/lookup /bin/lookup

WORKDIR /malware

ENTRYPOINT ["su-exec","malice","lookup"]
CMD ["--help"]

####################################################
####################################################

# Legion pilot database image: the official Postgres image, pinned by digest, minus gosu.
#
# gosu is the Go helper the official entrypoint uses to drop from root to `postgres`. It is the only
# Go binary in the image, and the build we pinned ships it compiled with Go 1.24.6, which carries a
# CRITICAL Go standard-library vulnerability (CVE-2025-68121) that has a fix (found by the CI image
# scan). Legion never needs it: the container runs as the `postgres` user (uid 70) from the start
# (docker-compose.pilot.yml `user:`), so the entrypoint never switches user, and the container needs
# no capabilities at all. Removing the binary removes the finding instead of excusing it.
FROM postgres:18.6-alpine@sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395
RUN rm -f /usr/local/bin/gosu /usr/local/bin/su-exec \
 && test "$(id -u postgres)" = 70
USER postgres

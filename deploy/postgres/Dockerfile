# Legion pilot database image: the official Postgres image, pinned by digest, minus gosu.
#
# gosu is the Go helper the official entrypoint uses to drop from root to `postgres`. It is the only
# Go binary in the image, and the build we pinned ships it compiled with Go 1.24.6, which carries a
# CRITICAL Go standard-library vulnerability (CVE-2025-68121) that has a fix (found by the CI image
# scan). Legion never needs it: the container runs as the `postgres` user (uid 70) from the start
# (docker-compose.pilot.yml `user:`), so the entrypoint never switches user, and the container needs
# no capabilities at all. Removing the binary removes the finding instead of excusing it.
FROM postgres:18.0-alpine@sha256:48c8ad3a7284b82be4482a52076d47d879fd6fb084a1cbfccbd551f9331b0e40
RUN rm -f /usr/local/bin/gosu /usr/local/bin/su-exec \
 && test "$(id -u postgres)" = 70
USER postgres

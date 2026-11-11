# tools/allocator/docker/Dockerfile — the RLN membership allocator on the
# released logosctl, next to a logos-blockchain node that runs the same way.
#
# Build context is tools/allocator (compose sets it), so lib.sh helpers and
# docker/bundles/*.lgx are reachable. Nothing is compiled here: logosctl is a
# release asset, the platform modules come from the official catalog, and
# this repo's modules come from docker/bundles/ (built by build-bundles.sh as
# PORTABLE variants — the released logosctl loads linux-amd64 / linux-arm64,
# not the nix -dev variants a nix-built logoscore loads).
#
# Mirrors logos-blockchain/Dockerfile: fetch the AppImage, patch its magic
# bytes (only matters under QEMU, harmless natively), extract it (no FUSE in
# containers), install the modules through a throwaway daemon session, then
# ship the extracted tool plus the installed modules as a read-only
# modules_dir in a slim runtime image.

FROM debian:trixie-slim AS builder
ARG LOGOSCTL_VERSION=0.3.2
ARG LIBP2P_VERSION=1.1.1
ARG LEZ_RLN_VERSION=5.1.0
# Delivery mode of the client (client-delivery.sh); the allocator never loads them.
ARG RLN_VERSION=0.12.0
ARG DELIVERY_VERSION=0.4.0
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends ca-certificates curl tar \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build

# logosctl: the tarball holds logosctl-<arch>.AppImage.
RUN case "$(uname -m)" in x86_64) P=x86_64-linux ;; aarch64) P=aarch64-linux ;; *) echo "no logosctl for $(uname -m)" >&2; exit 1 ;; esac \
    && curl -fsSL --retry 3 -o logosctl.tar.gz \
        "https://github.com/logos-co/logos-logoscore-cli/releases/download/${LOGOSCTL_VERSION}/logosctl-${P}.tar.gz" \
    && tar -xzf logosctl.tar.gz && rm logosctl.tar.gz \
    && mv logosctl-*.AppImage logosctl && chmod +x logosctl \
    && dd if=/dev/zero of=logosctl bs=1 count=3 seek=8 conv=notrunc \
    && ./logosctl --appimage-extract >/dev/null && mv squashfs-root ext-logosctl && rm logosctl

# Modules: the platform modules from the official catalog (built into
# logosctl) by version, this repo's modules from the bundles built on this
# host. The session dir is throwaway; only its modules/ tree is kept.
COPY docker/bundles/ /bundles/
ENV LOGOSCTL_CONFIG_DIR=/build/session
RUN ./ext-logosctl/AppRun daemon start --detach \
    && ./ext-logosctl/AppRun catalog refresh \
    && ./ext-logosctl/AppRun package install libp2p_module --version "$LIBP2P_VERSION" -y \
    && ./ext-logosctl/AppRun package install liblogos_lez_rln_module --version "$LEZ_RLN_VERSION" -y \
    && ./ext-logosctl/AppRun package install liblogos_rln_module --version "$RLN_VERSION" -y \
    && ./ext-logosctl/AppRun package install delivery_module --version "$DELIVERY_VERSION" -y \
    && for b in /bundles/*.lgx; do ./ext-logosctl/AppRun install "$b" -y; done \
    && ./ext-logosctl/AppRun daemon stop \
    && ls -1 /build/session/modules

# ---------------------------------------------------------------------------
FROM debian:trixie-slim
LABEL description="RLN membership allocator (rln_gifter_module on logosctl)"
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends ca-certificates curl python3 openssl procps \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/ext-logosctl /opt/logosctl
COPY --from=builder /build/session/modules /opt/modules
RUN ln -s /opt/logosctl/AppRun /usr/local/bin/logosctl
COPY docker/lib-ctl.sh docker/entrypoint.sh docker/client-entrypoint.sh docker/client-delivery.sh docker/client-events.py /usr/local/lib/allocator/
RUN chmod +x /usr/local/lib/allocator/entrypoint.sh /usr/local/lib/allocator/client-entrypoint.sh \
        /usr/local/lib/allocator/client-delivery.sh /usr/local/lib/allocator/client-events.py

# The session (daemon state, logs) lives on the data volume so a container
# replacement keeps nothing but the image's read-only modules_dir.
ENV LOGOSCTL_CONFIG_DIR=/var/lib/allocator/session \
    ALLOCATOR_DATA=/var/lib/allocator \
    ALLOWLIST_FILE=/etc/allocator/allowlist.txt \
    MODULES_DIR=/opt/modules
VOLUME ["/var/lib/allocator"]
ENTRYPOINT ["/usr/local/lib/allocator/entrypoint.sh"]

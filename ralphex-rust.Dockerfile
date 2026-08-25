# ralphex image with a Rust toolchain matching the dev machine.
#
# the stock ralphex image ships Go, not Rust. this adds what the repo's gates
# need: cargo build, cargo test, cargo clippy -- -D warnings -A dead_code,
# cargo fmt --check.
#
#   docker build -t ralphex-rust:latest - < ralphex-rust.Dockerfile
#   RALPHEX_IMAGE=ralphex-rust:latest ralphex docs/plans/<plan>.md
#
# note the "-" (build context on stdin): this Dockerfile COPYs nothing, and the
# repo carries a ~5GB target/ dir, so building with "." would upload all of it
# for no reason. do not "fix" this back to a dot without adding a .dockerignore.

FROM ghcr.io/umputun/ralphex-go:latest

USER root

# keep this in step with the dev machine's toolchain. it is pinned rather than
# "stable" on purpose: an unpinned container silently drifts away from the Mac
# again the next time upstream cuts a release.
ARG RUST_VERSION=1.97.1

# CARGO_HOME is world-writable and shared (the official rust images do the same)
# so the unprivileged `app` user that init.sh drops to can write the registry
# cache. /usr/local/cargo/bin goes first on PATH so nothing shadows the shims.
# these must be set BEFORE the install step, which reads $CARGO_HOME.
ENV RUSTUP_HOME=/usr/local/rustup \
	CARGO_HOME=/usr/local/cargo \
	PATH="/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:/home/app/go/bin"

# rustup, NOT alpine's rust package. alpine 3.23 ships rust 1.91.1 / rustfmt
# 1.8.0, six minor versions behind the Mac (1.97.1 / rustfmt 1.9.0), and the two
# rustfmt versions disagree — so `cargo fmt --check` passed or failed depending
# on where it ran. rustup publishes a real musl host toolchain, so pinning the
# exact version makes the gate mean the same thing in both places.
#
# the download MUST be named rustup-init: the binary dispatches on argv[0], and
# under any other name it behaves as a toolchain proxy and refuses to install.
#
# the cross-targets are baked in because rust-toolchain.toml lists them and
# rustup auto-installs listed targets on first use. containers run with --rm, so
# without this every ralphex run would re-download the same rust-std tarballs.
# procps-ng, not busybox ps: xray.rs shells out to `ps -eww -o pid=,user=,args=`
# and `ps -p <pid> -o comm=`, and busybox rejects both flag sets. Without it
# four process-tracking tests fail in this image for a reason that has nothing
# to do with the code, and `cargo test` here stops meaning what it means on the
# Mac — which is the one thing this image exists to guarantee. The package name
# is procps-ng on alpine 3.19+; `procps` resolves only through its provides, so
# spell it out. It installs /usr/bin/ps, which the PATH above reaches before
# busybox's /bin/ps.
RUN apk add --no-cache build-base pkgconf curl ca-certificates procps-ng \
	&& ARCH="$(apk --print-arch)" \
	&& curl -fsSL -o /tmp/rustup-init \
		"https://static.rust-lang.org/rustup/dist/${ARCH}-unknown-linux-musl/rustup-init" \
	&& chmod +x /tmp/rustup-init \
	&& /tmp/rustup-init -y --no-modify-path \
		--default-host "${ARCH}-unknown-linux-musl" \
		--default-toolchain "${RUST_VERSION}" \
		--profile minimal \
		-c rustfmt,clippy \
	&& rm /tmp/rustup-init \
	&& rustup target add \
		aarch64-apple-darwin \
		x86_64-apple-darwin \
		x86_64-unknown-linux-musl \
	&& chmod -R a+w "$CARGO_HOME" \
	&& rustc --version && cargo --version && rustfmt --version && cargo clippy --version

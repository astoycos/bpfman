From rustlang/rust:nightly as bpfd-build
WORKDIR /usr/src/bpfd
COPY ./ /usr/src/bpfd

RUN git clone https://github.com/libbpf/libbpf --branch v0.8.0

RUN apt-get update && apt-get install -y clang protobuf-compiler libelf-dev gcc-multilib

RUN rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu
RUN cargo install bpf-linker

# Compile the ebpf bytecode first
RUN cargo xtask build-ebpf --libbpf-dir /usr/src/bpfd/libbpf
# Compile only bpfd 
RUN cargo build --package bpfd

FROM fedora:36 as bpfd
WORKDIR /bpfd
# Just copy bytecode and bpfd binary maintaining directory structure due to 
# hardcoded path in bpfd
COPY --from=bpfd-build  /usr/src/bpfd/target/debug/bpfd /bpfd/target/debug/bpfd
COPY --from=bpfd-build  /usr/src/bpfd/target/bpfel-unknown-none/release/xdp_dispatcher.bpf.o bpfd/target/bpfel-unknown-none/release/xdp_dispatcher.bpf.o

CMD /bpfd/target/debug/bpfd

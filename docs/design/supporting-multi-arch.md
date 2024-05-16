# Supporting OCI bytecode Images across Multiple Architectures

Today bpfman has [defined a spec](../developer-guide/shipping-bytecode.md) for shipping eBPF programs via OCI images, however
it assumes the image builder explicitly knows the operating system
architecture where the program will be deployed.  Ultimately the spec needs to
support running on **any** valid linux architecture, this doc will describe
the changes needed for the spech to support such a task.

## Building eBPF programs for multiple architectures

eBPF programs only have two different completion targets which boil
down to programs compiled for big or little endian systems. This can be
clearly seen with the clang compiler:

```console
clang -print-targets

  Registered Targets:
    ...
    bpf         - BPF (host endian)
    bpfeb       - BPF (big endian)
    bpfel       - BPF (little endian)
    ...
```

Therefore, with those two targets a single eBPF program can essentially be compiled
to run successfully on any applicable linux target. However, oftentimes many
eBPF program types rely on kernel structures which may change across various
architectures, meaning that each architecture will need it's own program build.

TODO(astoycos) I want to dive into the "problem" a bit more here.

## Proposal

Today the bpfman project packages eBPF bytecode in OCI container images
using existing OCI layers and media types to ensure compatibility with existing
container registries and tooling such as quay.io and podman. Currently eBPF
program endianness is not referenced, and it is assumed to always be the host
endian of the build machine.  In order to allow a single eBPF bytecode image
to be run on any linux architecture, both big and little endian variants will need
to be packaged into each image, along with some necessary metadata to allow bpfman
to easily determine where each one is located in the image blob.



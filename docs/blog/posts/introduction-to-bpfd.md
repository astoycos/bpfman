# Introduction To Bpfd

In today's cloud ecosystem there's a high demand for low-level system access
to enable high performance observability, security and networking functionality
for applications. Historically a great deal of this kind of functionality has
been implemented in [userspace], but the ability to program these kinds of
things directly into the operating system can provide many benefits including
(but not limited to) performance. However, it has historically been very
challenging to add functionality directly to the operating system. In the past
you may have ended up developing and managing cumbersome [kernel modules][kmod],
but in recent years [eBPF] has emerged as a technology in the
[Linux Kernel][linux] looking to change all that.

eBPF is a simple and efficient way to dynamically load programs into the kernel
at runtime, with safety and performance provided by the kernel itself using a
Just-In-Time (JIT) compiler and verification process. There is a wide variety
of types of programs one can create with eBPF, which include everything from
networking applications to security systems.

We are however still fairly early in the eBPF journey and it's not all kittens
and rainbows: the process of developing, testing, deploying and maintaining
eBPF programs is not a road well traveled yet, and the story gets even more
complicated when you want to deploy your programs into more complicated setups,
such as a [Kubernetes] cluster. It was these kinds of problems which
instigated the creation of [Bpfd]: a system daemon for loading and managing eBPF
programs in both tradition systems and Kubernetes clusters. In this blog post
we'll discuss the problems Bpfd can help solve, and how to deploy and use it.

[userspace]:https://en.wikipedia.org/wiki/User_space_and_kernel_space
[kmod]:https://wiki.archlinux.org/title/Kernel_module
[eBPF]:https://ebpf.io
[linux]:https://kernel.org
[Kubernetes]:https://kubernetes.io
[Bpfd]:https://bpfd.dev

## Challenges with developing and deploying eBPF programs

TODO: explain the ergonomic challenges with developing, deploying and
managing eBPF programs in both traditional and Kubernetes environments.

## Introduction to Bpfd

TODO: overview of bpfd, with a high-level rundown of how to deploy and use it

## Introduction to the Kubernetes bpfd-operator

TODO

### Demonstration

TODO: a walkthrough for the reader to try out bpfd. Notes:
  a. use kind to create a local Kubernetes cluster
  b. deploy the bpfd-operator
  c. deploy one of the example applications as an EbpfProgram resource and test it out

## Joining the Bpfd community

If you're interested in Bpfd and want to get involved, you can connect with the
community multiple ways. If you have some simple questions, or need some help
feel free to [start a discussion][bpfd-disc]. If you find an issue, or you want
to request a new feature, please [create an issue][bpfd-iss]. If you want
something a little more synchronous, the project maintains a `#bpfd` channel on
[Kubernetes Slack][k8s-slack] and we have a [weekly community meeting][sync]
where everyone can join and bring topics to discuss about the project. We hope
to see you there!

[bpfd-disc]:https://github.com/bpfd-dev/bpfd/discussions/new/choose
[bpfd-iss]:https://github.com/bpfd-dev/bpfd/issues/new
[k8s-slack]:https://kubernetes.slack.com
[sync]:https://bpfd.dev/governance/meetings/

# Running the Examples as Non-Root on Selinux Distributions

Developer instances of kubernetes such as kind often set selinux to permissive
mode, ensuring the security subsystem does not interfere with the local
cluster operations.  However, in production distributions such as
Openshift, EKS, GKE and AWS where security is paramount, selinux and other
security subsystems are often enabled by default.  This among other things
presents unique challenges when determining how to deploy unprivileged applications
with bpfman.

In order to deploy the provided examples on selinux distributions, users must
first install the [security-profiles-operator](https://github.com/kubernetes-sigs/security-profiles-operator).
Which allows bpfman to deploy custom selinux policies allowing container users
access to bpf maps (i.e `map_read` and `map_write` actions).

It can easily be installed via operatorhub.io from [here](https://operatorhub.io/operator/security-profiles-operator).

Once the security-profiles-operator and bpfman are installed simply run:

```bash
make deploy-<EXAMPLE NAME>-selinux
```

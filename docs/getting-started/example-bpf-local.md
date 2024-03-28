# Deploying Example eBPF Programs On Local Host

This section describes running bpfman and the example eBPF programs on a local host.

## Example Walk Through

Assume the following command is run:

```console
cd bpfman/examples/go-xdp-counter/
sudo ./go-xdp-counter -iface eno3
```

The diagram below shows `go-xdp-counter` example, but the other examples operate in
a similar fashion.

![go-xdp-counter On Host](../img/gocounter-on-host.png)

Following the diagram (Purple numbers):

1. When `go-xdp-counter` userspace is started, it will send a gRPC request over unix
   socket to `bpfman-rpc` requesting `bpfman` to load the `go-xdp-counter` eBPF bytecode located
   on disk at `bpfman/examples/go-xdp-counter/bpf_bpfel.o` at a priority of 50 and on interface `eno3`.
   These values are configurable as we will see later, but for now we will use the defaults
   (except interface, which is required to be entered).
2. `bpfman` will load it's `dispatcher` eBPF program, which links to the `go-xdp-counter` eBPF program
   and return a kernel Program ID referencing the running program.
3. `bpfman list` can be used to show that the eBPF program was loaded.
4. Once the `go-xdp-counter` eBPF bytecode is loaded, the eBPF program will write packet counts
   and byte counts to a shared map.
5. `go-xdp-counter` userspace program periodically reads counters from the shared map and logs
   the value.

Below are the steps to launch `bpfman`, run some example programs, and use the `bpfman` CLI to load
and unload other eBPF programs.

## Launching bpfman

The most basic way to deploy this example is running directly on a host system.
First `bpfman` needs to be built and started.

### Build bpfman

Perform the following steps to build `bpfman`.
If this is your first time using bpfman, follow the instructions in
[Setup and Building bpfman](./building-bpfman.md) to setup the prerequisites for building.

```console
cd bpfman/
cargo build
```

### Start bpfman

When running bpfman, the RPC Server `bpfman-rpc` can be run as a long running process or a
systemd service.
Examples run the same, independent of how bpfman is deployed.

#### Run as a Long Lived Process

While learning and experimenting with `bpfman`, it may be useful to run `bpfman` in the foreground
(which requires a second terminal to run the `bpfman` CLI commands).
When run in this fashion, logs are dumped directly to the terminal.
For more details on how logging is handled in bpfman, see [Logging](../developer-guide/logging.md).

```console
sudo RUST_LOG=info ./target/debug/bpfman-rpc --timeout=0
[INFO  bpfman::utils] Log using env_logger
[INFO  bpfman::utils] Has CAP_BPF: true
[INFO  bpfman::utils] Has CAP_SYS_ADMIN: true
[WARN  bpfman::utils] Unable to read config file, using defaults
[INFO  bpfman_rpc::serve] Using no inactivity timer
[INFO  bpfman_rpc::serve] Using default Unix socket
[INFO  bpfman_rpc::serve] Listening on /run/bpfman-sock/bpfman.sock
```

When a build is run for bpfman, built binaries can be found in `./target/debug/`.
So when launching `bpfman-rpc` and calling `bpfman` CLI commands, the binary must be in the $PATH
or referenced directly:

```console
sudo ./target/debug/bpfman list
```

For readability, the remaining sample commands will assume the `bpfman` CLI binary is in the $PATH,
so `./target/debug/` will be dropped.

#### Run as a systemd Service

Run the following command to copy the `bpfman` CLI and `bpfman-rpc` binaries to `/usr/sbin/` and
copy `bpfman.socket` and `bpfman.service` files to `/usr/lib/systemd/system/`.
This option will also enable and start the systemd services:

```console
sudo ./scripts/setup.sh install
```

`bpfman` CLI is now in $PATH, so `./targer/debug/` is not needed:

```console
sudo bpfman list
```

To view logs, use `journalctl`:

```console
sudo journalctl -f -u bpfman.service -u bpfman.socket
Mar 27 09:13:54 server-calvin systemd[1]: Listening on bpfman.socket - bpfman API Socket.
  <RUN "sudo ./go-kprobe-counter">
Mar 27 09:15:43 server-calvin systemd[1]: Started bpfman.service - Run bpfman as a service.
Mar 27 09:15:43 server-calvin bpfman-rpc[2548091]: Log using journald
Mar 27 09:15:43 server-calvin bpfman-rpc[2548091]: Has CAP_BPF: true
Mar 27 09:15:43 server-calvin bpfman-rpc[2548091]: Has CAP_SYS_ADMIN: true
Mar 27 09:15:43 server-calvin bpfman-rpc[2548091]: Unable to read config file, using defaults
Mar 27 09:15:43 server-calvin bpfman-rpc[2548091]: Using a Unix socket from systemd
Mar 27 09:15:43 server-calvin bpfman-rpc[2548091]: Using inactivity timer of 15 seconds
Mar 27 09:15:43 server-calvin bpfman-rpc[2548091]: Listening on /run/bpfman-sock/bpfman.sock
Mar 27 09:15:43 server-calvin bpfman-rpc[2548091]: Unable to read config file, using defaults
Mar 27 09:15:43 server-calvin bpfman-rpc[2548091]: Unable to read config file, using defaults
Mar 27 09:15:43 server-calvin bpfman-rpc[2548091]: Starting Cosign Verifier, downloading data from Sigstore TUF repository
Mar 27 09:15:45 server-calvin bpfman-rpc[2548091]: Loading program bytecode from file: /home/<USER>/src/bpfman/examples/go-kprobe-counter/bpf_bpfel.o
Mar 27 09:15:45 server-calvin bpfman-rpc[2548091]: Added probe program with name: kprobe_counter and id: 7568
Mar 27 09:15:48 server-calvin bpfman-rpc[2548091]: Unable to read config file, using defaults
Mar 27 09:15:48 server-calvin bpfman-rpc[2548091]: Removing program with id: 7568
Mar 27 09:15:58 server-calvin bpfman-rpc[2548091]: Shutdown Unix Handler /run/bpfman-sock/bpfman.sock
Mar 27 09:15:58 server-calvin systemd[1]: bpfman.service: Deactivated successfully.
```

##### Additional Notes

To update the configuration settings associated with running `bpfman` as a service, edit the
service configuration files:

```console
sudo vi /usr/lib/systemd/system/bpfman.socket
sudo vi /usr/lib/systemd/system/bpfman.service
sudo systemctl daemon-reload
```

If `bpfman` CLI or `bpfman-rpc` is rebuilt, the following command can be run to install the update
binaries without tearing down `bpfman`.
The services are automatically restarted.

```console
sudo ./scripts/setup.sh reinstall
```

To unwind all the changes, stop `bpfman` and remove all related files from the system, run the
following script:

```console
sudo ./scripts/setup.sh uninstall
```

#### Preferred Method to Start bpfman

In order to call into the `bpfman` Library, the calling process must be privileged.
In order to load and unload eBPF, the kernel requires a set of powerful capabilities.
Long lived privileged processes are more vulnerable to attack than short lived processes.
When `bprman-rpc` is run as a systemd service, it is leveraging
[socket activation](https://man7.org/linux/man-pages/man1/systemd-socket-activate.1.html).
This means that it loads a `bpfman.socket` and `bpfman.service` file.
The socket service is the long lived process, which doesn't have any special permissions.
The service that runs `bpfman-rpc` is only started when there is a request on the socket,
and then `bpfman-rpc` stops itself after an inactivity timeout.

> For security reasons, it is recommended to run `bprman-rpc` as a systemd service when running
on a local host.
For local development, some may find it useful to run `bprman-rpc` as a long lived process.

When run as a systemd service, the set of linux capabilities are limited to only the required set.
If permission errors are encountered, see [Linux Capabilities](../developer-guide/linux-capabilities.md)
for help debugging.

## Running Example Programs

[Example eBPF Programs](./example-bpf.md) describes how the example programs work,
how to build them, and how to run the different examples.
[Build](./example-bpf.md/#building-locally) the `go-xdp-counter` program before continuing.

To run the `go-xdp-counter` program, determine the host interface to attach the eBPF
program to and then start the go program.
In this example, `eno3` will be used, as shown in the diagram at the top of the page. 
The output should show the count and total bytes of packets as they pass through the
interface as shown below:

```console
sudo ./go-xdp-counter --iface eno3
2023/07/17 17:43:58 Using Input: Interface=eno3 Priority=50 Source=/home/<$USER>/src/bpfman/examples/go-xdp-counter/bpf_bpfel.o
2023/07/17 17:43:58 Program registered with id 6211
2023/07/17 17:44:01 4 packets received
2023/07/17 17:44:01 580 bytes received

2023/07/17 17:44:04 4 packets received
2023/07/17 17:44:04 580 bytes received

2023/07/17 17:44:07 8 packets received
2023/07/17 17:44:07 1160 bytes received

:
```

In another terminal, use the CLI to show the `go-xdp-counter` eBPF bytecode was loaded.

```console
sudo bpfman list
 Program ID  Name       Type  Load Time
 6211        xdp_stats  xdp   2023-07-17T17:43:58-0400
```

Finally, press `<CTRL>+c` when finished with `go-xdp-counter`.

```console
:

2023/07/17 17:44:34 28 packets received
2023/07/17 17:44:34 4060 bytes received

^C2023/07/17 17:44:35 Exiting...
2023/07/17 17:44:35 Unloading Program: 6211
```

## Using CLI to Manage eBPF Programs

bpfman provides a CLI to interact with the `bpfman` Library.
Find a deeper dive into CLI syntax in [CLI Guide](./cli-guide.md).
We will load the simple `xdp-pass` program, which allows all traffic to pass through the attached
interface, `eno3` in this example.
The source code,
[xdp_pass.bpf.c](https://github.com/bpfman/bpfman/blob/main/tests/integration-test/bpf/xdp_pass.bpf.c),
is located in the [integration-test](https://github.com/bpfman/bpfman/tree/main/tests/integration-test)
directory and there is also a prebuilt image:
[quay.io/bpfman-bytecode/xdp_pass:latest](https://quay.io/bpfman-bytecode/).

```console
sudo bpfman load image --image-url quay.io/bpfman-bytecode/xdp_pass:latest xdp --iface eno3 --priority 100
 Bpfman State
---------------
 Name:          pass
 Image URL:     quay.io/bpfman-bytecode/xdp_pass:latest
 Pull Policy:   IfNotPresent
 Global:        None
 Metadata:      None
 Map Pin Path:  /run/bpfman/fs/maps/6213
 Map Owner ID:  None
 Map Used By:   6213
 Priority:      100
 Iface:         eno3
 Position:      0
 Proceed On:    pass, dispatcher_return

 Kernel State
----------------------------------
 Program ID:                       6213
 Name:                             pass
 Type:                             xdp
 Loaded At:                        2023-07-17T17:48:10-0400
 Tag:                              4b9d1b2c140e87ce
 GPL Compatible:                   true
 Map IDs:                          [2724]
 BTF ID:                           2834
 Size Translated (bytes):          96
 JITed:                            true
 Size JITed (bytes):               67
 Kernel Allocated Memory (bytes):  4096
 Verified Instruction Count:       9
```

`bpfman load image` returns the same data as a `bpfman get` command.
From the output, the Program Id of `6213` can be found in the `Kernel State` section.
The Program Id can be used to perform a `bpfman get` to retrieve all relevant program
data and a `bpfman unload` when the program needs to be unloaded.

```console
sudo bpfman list
 Program ID  Name  Type  Load Time
 6213        pass  xdp   2023-07-17T17:48:10-0400
```

We can recheck the details about the loaded program with the `bpfman get` command:

```console
sudo bpfman get 6213
 Bpfman State
---------------
 Name:          pass
 Image URL:     quay.io/bpfman-bytecode/xdp_pass:latest
 Pull Policy:   IfNotPresent
 Global:        None
 Metadata:      None
 Map Pin Path:  /run/bpfman/fs/maps/6213
 Map Owner ID:  None
 Map Used By:   6213
 Priority:      100
 Iface:         eno3
 Position:      0
 Proceed On:    pass, dispatcher_return

 Kernel State
----------------------------------
 Program ID:                       6213
 Name:                             pass
 Type:                             xdp
 Loaded At:                        2023-07-17T17:48:10-0400
 Tag:                              4b9d1b2c140e87ce
 GPL Compatible:                   true
 Map IDs:                          [2724]
 BTF ID:                           2834
 Size Translated (bytes):          96
 JITed:                            true
 Size JITed (bytes):               67
 Kernel Allocated Memory (bytes):  4096
 Verified Instruction Count:       9
```

Then unload the program:

```console
sudo bpfman unload 6213
```

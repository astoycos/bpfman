// SPDX-License-Identifier: (MIT OR Apache-2.0)
// Copyright Authors of bpfman

use std::{fs::File, process};

use anyhow::{bail, Context};
use aya::programs::{links::FdLink, uprobe::UProbeLink, ProbeKind, UProbe};
use clap::{Args, Parser, Subcommand};
use log::debug;
use nix::sched::{setns, CloneFlags};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Attach a uprobe program in the given namespace.
    Uprobe(UprobeArgs),
    // TODO: add additional commands: Kprobe, etc.
}

#[derive(Debug, Args)]
struct UprobeArgs {
    /// Required: path to pinned entry for bpf program on a bpffs.
    #[clap(short, long, verbatim_doc_comment)]
    program_pin_path: String,

    /// Optional: Function to attach the uprobe to.
    #[clap(short, long)]
    fn_name: Option<String>,

    /// Required: Offset added to the address of the target function (or
    /// beginning of target if no function is identified). Offsets are supported
    /// for uretprobes, but use with caution because they can result in
    /// unintended side effects.
    #[clap(short, long, verbatim_doc_comment)]
    offset: u64,

    /// Required: Library name or the absolute path to a binary or library.
    /// Example: --target "libc".
    #[clap(short, long, verbatim_doc_comment)]
    target: String,

    /// Optional: Whether the program is a uretprobe.
    /// [default: false]
    #[clap(short, long, verbatim_doc_comment)]
    retprobe: bool,

    /// Optional: Only execute uprobe for given process identification number
    /// (PID). If PID is not provided, uprobe executes for all PIDs.
    #[clap(long, verbatim_doc_comment)]
    pid: Option<i32>,

    /// Required: Host PID of namespace to attach the uprobe in.
    #[clap(short, long)]
    namespace_pid: i32,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    debug!("bpfman-ns started");

    has_cap(caps::CapSet::Effective, caps::Capability::CAP_BPF);
    has_cap(caps::CapSet::Effective, caps::Capability::CAP_SYS_ADMIN);
    has_cap(caps::CapSet::Effective, caps::Capability::CAP_SYS_CHROOT);

    let bpfman_pid = process::id();

    let cli = Cli::parse();
    debug!("command: {:?}", cli);
    match cli.command {
        Commands::Uprobe(args) => execute_uprobe_attach(args, bpfman_pid),
    }
}

// Debug function to print root directory contents.
fn _ls_dir() {
    let entries = std::fs::read_dir("/").unwrap();

    for entry in entries {
        debug!("Name: {}", entry.unwrap().path().display())
    }
}

fn has_cap(cset: caps::CapSet, cap: caps::Capability) {
    debug!("Has {}: {}", cap, caps::has_cap(None, cset, cap).unwrap());
}

fn execute_uprobe_attach(args: UprobeArgs, bpfman_pid: u32) -> anyhow::Result<()> {
    let bpfman_mnt_file_path = format!("/proc/{}/ns/mnt", bpfman_pid);
    let target_mnt_file_path = format!("/proc/{}/ns/mnt", args.namespace_pid);

    debug!(
        "bpfman_mnt_file_path: {:?}, target_mnt_file_path: {:?}",
        bpfman_mnt_file_path, target_mnt_file_path
    );

    let bpfman_mnt_file = match File::open(bpfman_mnt_file_path) {
        Ok(file) => file,
        Err(e) => bail!("error opening bpfman file: {}", e),
    };

    let target_mnt_file = match File::open(target_mnt_file_path) {
        Ok(file) => file,
        Err(e) => bail!("error opening target file: {}", e),
    };

    let mut uprobe = UProbe::from_pin(args.program_pin_path.clone(), ProbeKind::UProbe)
        .context("failed to get UProbe from pin file")?;

    // Set namespace to target namespace
    let setns_result = setns(target_mnt_file, CloneFlags::CLONE_NEWNS);
    match setns_result {
        Ok(_) => debug!(
            "set ns to target PID {} mnt namespace succeeded",
            args.namespace_pid
        ),
        Err(e) => {
            debug!(
                "failed to set ns to target PID {} mnt namespace",
                args.namespace_pid
            );
            bail!(
                "failed to set ns to target PID {} mnt namespace. Error: {}",
                args.namespace_pid,
                e
            );
        }
    }

    let link_id = uprobe.attach(args.fn_name.as_deref(), args.offset, args.target, args.pid)?;

    // Set namespace back to bpfman namespace
    let setns_result = setns(bpfman_mnt_file, CloneFlags::CLONE_NEWNS);
    match setns_result {
        Ok(_) => debug!(
            "set ns back to bpfman PID {} mnt namespace succeeded",
            bpfman_pid
        ),
        Err(e) => {
            debug!(
                "failed to set ns back to bpfman PID {} mnt namespace",
                bpfman_pid
            );
            bail!(
                "failed to set ns back to target PID {} mnt namespace. Error: {}",
                bpfman_pid,
                e
            );
        }
    }

    // pin_uprobe_fd_link(uprobe, link_id, args.program_pin_path)?;

    let owned_link: UProbeLink = uprobe
        .take_link(link_id)
        .expect("take_link failed for uprobe");
    let fd_link: FdLink = owned_link
        .try_into()
        .expect("unable to get owned uprobe attach link");

    fd_link.pin(format!("{}_link", args.program_pin_path))?;

    Ok(())
}

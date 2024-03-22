use std::{process::Command};

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    /// Optional: Build the release target
    #[clap(long)]
    pub release: bool,
}

/// Run unit-test
pub fn unit_test(opts: Options) -> Result<(), anyhow::Error> {
    let mut args = vec!["test"];
    if opts.release {
        args.push("--release")
    }
    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    Ok(())
}

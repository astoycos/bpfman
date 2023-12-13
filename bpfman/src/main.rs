// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of bpfman

use clap::Parser;
use sled::{Config, Db};
use lazy_static::lazy_static;
use bpfman_api::util::directories::STDIR_DB;

mod bpf;
mod cli;
mod command;
mod dispatcher_config;
mod errors;
mod multiprog;
mod oci_utils;
mod rpc;
mod serve;
mod static_program;
mod storage;
mod utils;

const BPFMAN_ENV_LOG_LEVEL: &str = "RUST_LOG";

lazy_static! {
    pub static ref BPFMAN_DB: Db  = {
        Config::default()
        .path(STDIR_DB)
        .open()
        .expect("Unable to open database")
    };
}

fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    cli.command.execute()
}

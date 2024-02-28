// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of bpfman
use std::{thread, time::Duration};

use anyhow::bail;
use clap::Parser;
use lazy_static::lazy_static;
use log::info;
use sled::{Config as SledConfig, Db};

use crate::{oci_utils::ImageManager, utils::open_config_file};

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

#[cfg(not(test))]
fn get_db_config() -> SledConfig {
    SledConfig::default().path(bpfman_api::util::directories::STDIR_DB)
}

#[cfg(test)]
fn get_db_config() -> SledConfig {
    SledConfig::default().temporary(true)
}

fn init_database(sled_config: SledConfig) -> anyhow::Result<Db> {
    let config = open_config_file();
    for _ in 1..config.database.as_ref().map_or(4, |d| d.max_retries) {
        if let Ok(db) = sled_config.open() {
            info!("Successfully opened database");
            return Ok(db);
        } else {
            info!(
                "Failed to open database, retrying after {} milliseconds",
                config.database.clone().map_or(500, |v| v.millisec_delay)
            );
            thread::sleep(Duration::from_millis(
                config.database.as_ref().map_or(500, |d| d.millisec_delay),
            ));
        }
    }
    bail!("Timed out");
}

fn init_image_manager() -> anyhow::Result<ImageManager> {
    let config = open_config_file();
    ImageManager::new(config.signing.as_ref().map_or(true, |s| s.allow_unsigned))
}

lazy_static! {
    pub static ref ROOT_DB: Db =
        init_database(get_db_config()).expect("Unable to open root database");
}

lazy_static! {
    pub static ref IMAGE_MANAGER: ImageManager =
        init_image_manager().expect("Unable to initialize image manager");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = cli::args::Cli::parse();
    cli.command.execute().await
}

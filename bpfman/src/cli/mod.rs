// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of bpfman

pub(crate) mod args;
mod get;
mod image;
mod list;
mod load;
mod system;
mod table;
mod unload;

use anyhow::anyhow;
use args::Commands;
use get::execute_get;
use list::execute_list;
use unload::execute_unload;

use crate::{bpf::BpfManager, cli::system::initialize_bpfman, utils::open_config_file};

impl Commands {
    pub(crate) async fn execute(&self) -> Result<(), anyhow::Error> {
        initialize_bpfman()?;

        let config = open_config_file();

        let mut bpf_manager = BpfManager::new(config.clone(), None);

        match self {
            Commands::Load(l) => l.execute(&mut bpf_manager),
            Commands::Unload(args) => execute_unload(&mut bpf_manager, args),
            Commands::List(args) => execute_list(&mut bpf_manager, args),
            Commands::Get(args) => {
                execute_get(&mut bpf_manager, args).map_err(|e| anyhow!("get error: {e}"))
            }
            Commands::Image(i) => i.execute(&mut bpf_manager),
            Commands::System(s) => s.execute(&config).await,
        }?;

        Ok(())
    }
}

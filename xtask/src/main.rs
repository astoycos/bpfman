mod build_ebpf;
mod integration_test;
mod protobuf;
mod run;

use std::process::exit;

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    BuildEbpf(build_ebpf::Options),
    BuildProto(protobuf::Options),
    BuildK8sCRIProto(protobuf::Options),
    Run(run::Options),
    IntegrationTest(integration_test::Options),
}

#[tokio::main]
async fn main() {
    let opts = Options::parse();

    use Command::*;
    let ret = match opts.command {
        BuildEbpf(opts) => build_ebpf::build_ebpf(opts),
        BuildProto(opts) => protobuf::build(opts),
        BuildK8sCRIProto(opts) => protobuf::build_k8s_cri(opts).await,
        Run(opts) => run::run(opts),
        IntegrationTest(opts) => integration_test::test(opts),
    };

    if let Err(e) = ret {
        eprintln!("{e:#}");
        exit(1);
    }
}

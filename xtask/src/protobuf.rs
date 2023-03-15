use std::{path::PathBuf, process::Command, string::String};

use clap::Parser;
use lazy_static::lazy_static;
use serde_json::Value;
use hyper::Client;
use tokio::io::AsyncWriteExt;
use tokio::fs::OpenOptions;
use hyper::{body, Uri};
use hyper_tls::HttpsConnector;

#[derive(Debug, Parser)]
pub struct Options {}

lazy_static! {
    pub static ref WORKSPACE_ROOT: String = workspace_root();
}

fn workspace_root() -> String {
    let output = Command::new("cargo").arg("metadata").output().unwrap();
    if !output.status.success() {
        panic!("unable to run cargo metadata")
    }
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: Value = serde_json::from_str(&stdout).unwrap();
    v["workspace_root"].as_str().unwrap().to_string()
}

pub fn build(_opts: Options) -> anyhow::Result<()> {
    let root = PathBuf::from(WORKSPACE_ROOT.to_string());
    let out_dir = root.join("bpfd-api/src");
    let proto_dir = root.join("proto");

    let protos = &["bpfd.proto"];
    let includes = &[proto_dir.to_str().unwrap()];
    tonic_build::configure()
        .out_dir(out_dir)
        .compile(protos, includes)?;

    // protoc -I=./bpfd/proto --go_out=paths=source_relative:./clients/gobpfd ./bpfd/proto/bpfd.proto
    let status = Command::new("protoc")
        .current_dir(&root)
        .args([
            "-I=./proto",
            "--go_out=paths=source_relative:./clients/gobpfd/v1",
            "bpfd.proto",
        ])
        .status()
        .expect("failed to build bpf program");
    assert!(status.success());
    let status = Command::new("protoc")
        .current_dir(&root)
        .args([
            "-I=./proto",
            "--go-grpc_out=./clients/gobpfd/v1",
            "--go-grpc_opt=paths=source_relative",
            "bpfd.proto",
        ])
        .status()
        .expect("failed to build bpf program");
    assert!(status.success());
    Ok(())
}

pub async fn build_k8s_cri(_opts: Options) -> anyhow::Result<()> {
    let root = PathBuf::from(WORKSPACE_ROOT.to_string());
    let out_dir = root.join("k8s-cri-api/src");
    let proto_dir = root.join("proto");
    // Pull fresh version of k8s CRI API
    let k8s_cri_proto_url = "https://raw.githubusercontent.com/kubernetes/cri-api/release-1.26/pkg/apis/runtime/v1/api.proto".parse::<Uri>().unwrap();

    fetch_url(k8s_cri_proto_url, proto_dir.clone()).await?; 

    // Remove gogoproto directives
    let output = Command::new("sed")
        .current_dir(&root)
        .args([
            "-i", 
            "/gogoproto/d",
            "./proto/api.proto"
        ])
        .output()
        .unwrap();
    if !output.status.success() {
        print!("Stdout: {:#?}\nStderr: {:#?}", String::from_utf8_lossy(&output.stderr), String::from_utf8_lossy(&output.stdout));
        panic!("unable to remove gogoproto directives from k8s cri proto file")
    }

    let protos = &["api.proto"];
    let includes = &[proto_dir.to_str().unwrap()];
    tonic_build::configure()
        .out_dir(out_dir)
        .compile(protos, includes)?;

    // protoc -I=./bpfd/proto --go_out=paths=source_relative:./clients/gobpfd ./bpfd/proto/bpfd.proto
    // let status = Command::new("protoc")
    //     .current_dir(&root)
    //     .args([
    //         "-I=./proto",
    //         "api.proto",
    //     ])
    //     .status()
    //     .expect("failed to build bpf program");
    // assert!(status.success());
    // let status = Command::new("protoc")
    //     .current_dir(&root)
    //     .args([
    //         "-I=./proto",
    //         "api.proto",
    //     ])
    //     .status()
    //     .expect("failed to build bpf program");
    // assert!(status.success());
    Ok(())
}

async fn fetch_url(url: Uri, out_path: PathBuf) -> anyhow::Result<()> {
    let https =HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    let file_path =  out_path.join(String::from(url.path().split('/').last().unwrap()));

    let res = client
        // Fetch the url...
        .get(url).await?;
        // And then, if we get a response back...
    
    println!("Response: {}", res.status());
    println!("Headers: {:#?}", res.headers());
    
    // Always overwite file
    let mut file = OpenOptions::new().write(true).create(true).open(file_path).await?;

    let bytes = body::to_bytes(res.into_body()).await?;

    file.write_all(&bytes).await?;

    Ok(())
}
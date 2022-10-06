// SPDX-License-Identifier: (MIT OR Apache-2.0)
// Copyright Authors of bpfd
use std::{env, path::Path, fs::File, collections::HashMap};
use flate2::read::GzDecoder;
use log::{debug, warn};
use oci_distribution::{client, manifest, secrets::RegistryAuth, Client, Reference};
use serde::Deserialize;
use serde_json::Value;
use tar::Archive;
use thiserror::Error;
use base64;

const CONTAINERIZED_BYTECODE_PATH: &str = "/var/bpfd/bytecode/";

#[derive(Debug, Deserialize, Default)]
pub struct ContainerImageMetadata {
    #[serde(rename(deserialize = "io.ebpf.program_name"))]
    pub name: String,
    #[serde(rename(deserialize = "io.ebpf.section_name"))]
    pub section_name: String,
    #[serde(rename(deserialize = "io.ebpf.program_type"))]
    pub program_type: String,
    #[serde(rename(deserialize = "io.ebpf.filename"))]
    pub filename: String,
}

#[derive(Debug, Error)]
pub enum ImageError {
    #[error("Failed to Parse bytecode Image URL: {0}")]
    InvalidImageUrl(#[source] oci_distribution::ParseError),
    #[error("Failed to pull bytecode Image manifest: {0}")]
    ImageManifestPullFailure(#[source] oci_distribution::errors::OciDistributionError),
    #[error("Failed to pull bytecode Image: {0}")]
    BytecodeImagePullFailure(#[source] oci_distribution::errors::OciDistributionError),
    #[error("Failed to extract bytecode from Image")]
    BytecodeImageExtractFailure,
    #[error("Failed to build Auth FilePath")]
    AuthFilePathBuildFailure,    
    #[error("Failed to open auth file: {0}")]
    OpenAuthFileFailure(#[source] std::io::Error),
    #[error("Failed to parse auth file: {0}")]
    AuthFileParseFailure(#[source] serde_json::Error),
    #[error("Failed to decode auth file entry")]
    AuthFileDecodeFailure,
}

#[derive(Deserialize)]
pub(crate) struct AuthConfig {
    pub(crate) auth: Option<String>,
    
}

// Intentionally leave out creds_store and creds_helpers for now since oci-distribution
// crate doesn't support authentication with tokens yet
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ContainerConfig {
    pub(crate) auths: Option<HashMap<String, AuthConfig>>,
    // pub(crate) creds_store: Option<String>,
    // pub(crate) cred_helpers: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ProgramOverrides {
    pub path: String,
    pub image_meta: ContainerImageMetadata,
}

pub async fn pull_bytecode(image_url: &String) -> Result<ProgramOverrides, anyhow::Error> {
    debug! {"Pulling bytecode from image path: {}", image_url}
    let image: Reference = image_url.parse().map_err(ImageError::InvalidImageUrl)?;

    let protocol = client::ClientProtocol::Https;

    // TODO(astoycos): Add option/flag to authenticate against private image repositories
    // https://github.com/redhat-et/bpfd/issues/119
    let auth = get_registry_auth(&image)?;

    let config = client::ClientConfig {
        protocol,
        ..Default::default()
    };

    let mut client = Client::new(config);

    let (image_manifest, _, config_contents) = client
        .pull_manifest_and_config(&image, &auth)
        .await
        .map_err(ImageError::ImageManifestPullFailure)?;

    debug!("Raw container image manifest {}", image_manifest);

    let image_config: Value = serde_json::from_str(&config_contents).unwrap();
    debug!("Raw container image config {}", image_config);

    // Deserialize image metadata(labels) from json config
    let image_labels: ContainerImageMetadata =
        serde_json::from_str(&image_config["config"]["Labels"].to_string())?;

    let image_content = client
        .pull(
            &image,
            &auth,
            vec![
                manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
                manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
            ],
        )
        .await
        .map_err(ImageError::BytecodeImagePullFailure)?
        .layers
        .into_iter()
        .next()
        .map(|layer| layer.data)
        .ok_or(ImageError::BytecodeImageExtractFailure)?;

    let bytecode_path = CONTAINERIZED_BYTECODE_PATH.to_owned() + &image_labels.filename;

    // Create bytecode directory if not exists
    std::fs::create_dir_all(CONTAINERIZED_BYTECODE_PATH)?;

    // Data is of OCI media type "application/vnd.oci.image.layer.v1.tar+gzip" or
    // "application/vnd.docker.image.rootfs.diff.tar.gzip"
    // decode and unpack to access bytecode
    let unzipped_tarball = GzDecoder::new(image_content.as_slice());
    let mut tarball = Archive::new(unzipped_tarball);
    tarball.unpack(CONTAINERIZED_BYTECODE_PATH).unwrap();

    Ok(ProgramOverrides {
        path: bytecode_path,
        image_meta: image_labels,
    })
}

/// get_registry_auth searches the local fs for remote container registry credentials. 
/// The default path for reading credentials is ${XDG_RUNTIME_DIR}/containers/auth.json, 
/// but as a backup it also looks in $HOME/.docker/config.json or what's specified 
/// within the "DOCKER_CONFIG" environment variable. 
fn get_registry_auth(image_ref: &Reference) -> Result<RegistryAuth, ImageError> {     
    let registry = image_ref.registry();

    let container_auth_path = env::var_os("XDG_RUNTIME_DIR")
        .map(|home| Path::new(&home).join("containers/auth.json"))
        .ok_or(ImageError::AuthFilePathBuildFailure)?;
    
    // Either return ~/.docker or what's defined in the $DOCKER_CONFIG Env Var
    let docker_auth_path = env::var_os("DOCKER_CONFIG")
        .map(|dir| Path::new(&dir).to_path_buf())
        .or_else(|| env::var_os("HOME").map(|home| Path::new(&home).join(".docker/config.json")))
        .ok_or(ImageError::AuthFilePathBuildFailure)?;

    let container_auth_file = File::open(container_auth_path)
    .map_err(ImageError::OpenAuthFileFailure)?;

    let container_auths = serde_json::from_reader::<_, ContainerConfig>(container_auth_file).
    map_err(ImageError::AuthFileParseFailure)?;

    match parse_registry_auth(container_auths, registry)? { 
        Some(creds) => return Ok(creds),
        None => warn!("No credentials found in container auths for registry {}", registry),
    };

    let docker_auth_file = File::open(docker_auth_path)
    .map_err(ImageError::OpenAuthFileFailure)?;
    
    let docker_auths = serde_json::from_reader::<_, ContainerConfig>(docker_auth_file).
    map_err(ImageError::AuthFileParseFailure)?;

    match parse_registry_auth(docker_auths, registry)? { 
        Some(credential) => Ok(credential),
        None => {
            warn!("No credentials found in container auths or docker auths for registry {}", registry);
            Ok(RegistryAuth::Anonymous)
        }
    }

}


fn parse_registry_auth(container_auths: ContainerConfig, registry: &str) -> Result<Option<RegistryAuth>, ImageError> {
    if let Some(mut auth) = container_auths.auths {
        // Get only registries we care about, i.e keys containing the registry name
        let entry = auth
        .drain()
        .find_map(|(k,v)| k.contains(registry).then_some(v))
        .ok_or(ImageError::AuthFileDecodeFailure)?
        .auth
        .ok_or(ImageError::AuthFileDecodeFailure)?;
            
        debug!("Found auth for {}: {}", registry, entry);
        
        let decoded_auth = base64::decode(entry)
        .map_err(|_| ImageError::AuthFileDecodeFailure)?;

        let decoded_auth_str = std::str::from_utf8(&decoded_auth)
        .map_err(|_| ImageError::AuthFileDecodeFailure)?;
        
        let usr_pass: Vec<&str> = decoded_auth_str.split(':').collect();
        
        return Ok(Some(RegistryAuth::Basic(String::from(usr_pass[0]), String::from(usr_pass[1]))))
    }

    Ok(None)
}
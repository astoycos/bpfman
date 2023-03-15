use std::convert::TryFrom;

use k8s_cri_api::v1::runtime_service_client::RuntimeServiceClient;
use k8s_cri_api::v1::image_service_client::ImageServiceClient;
use k8s_cri_api::v1::{ListContainersRequest, ListImagesRequest, PullImageRequest, ImageSpec, ImageFsInfoRequest, CreateContainerRequest, ContainerConfig, Mount, RunPodSandboxRequest, PodSandboxConfig, PodSandboxMetadata, ImageStatusRequest};
use tokio::net::UnixStream;
use tonic::transport::{Endpoint, Uri};
use tonic::{Request, Status};
use tower::service_fn;
use std::collections::HashMap;

// Containerd namespace is hardwired with https://github.com/containerd/containerd/blob/main/pkg/cri/cri.go#L79
#[tokio::main]
async fn main() {
    let path = "/run/containerd/containerd.sock";
    //let path = "/run/docker.sock ";
    let channel = Endpoint::try_from("http://[::]")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| UnixStream::connect(path)))
        .await
        .expect("Could not create client.");

    let mut client = RuntimeServiceClient::with_interceptor(channel.clone(), intercept);

    let request = tonic::Request::new(ListContainersRequest { filter: None });
    
    let response = client
         .list_containers(request)
         .await
         .expect("Request failed.");
    println!("{:?}", response);

    let mut client = ImageServiceClient::with_interceptor(channel.clone(), intercept);

    let request = Request::new(ListImagesRequest { filter: None });
    
    let response = client
         .list_images(request)
         .await
         .expect("Request failed.");
    println!("{:?}", response);

    let request = Request::new(PullImageRequest { 
        image: Some(
            ImageSpec{
                image: "quay.io/bpfd-bytecode/xdp_pass:latest".to_string(),
                annotations: HashMap::new(),
            }),
        auth: None,
        sandbox_config: None,
    });

    let response = client
    .pull_image(request)
    .await
    .expect("Request failed.");
    println!("{:?}", response);

    let request = Request::new(ImageFsInfoRequest{});

    let response = client
    .image_fs_info(request)
    .await
    .expect("Request failed.");
    println!("{:?}", response);

    let request = Request::new(ImageStatusRequest{
        image: Some(
            ImageSpec{
                image: "quay.io/bpfd-bytecode/xdp_pass:latest".to_string(),
                annotations: HashMap::new(),
            }),
        verbose: true
    });

    let response = client
    .image_status(request)
    .await
    .expect("Request failed.");
    println!("{:#?}", response);

    // let mut client = RuntimeServiceClient::with_interceptor(channel.clone(), intercept);

    // let request = tonic::Request::new(RunPodSandboxRequest{
    //     config: Some(PodSandboxConfig {
    //         metadata: Some(PodSandboxMetadata { 
    //             name: "xdp_pass".to_string(),
    //             ..Default::default()

    //         }),
    //         ..Default::default()
    //     }),
        
        
    // });
    
    // let response = client
    //      .run_pod_sandbox(request)
    //      .await
    //      .expect("Request failed.");
    // println!("{:?}", response);

    // let request = tonic::Request::new(CreateContainerRequest{
    //     pod_sandbox_id: "xdp_pass".to_string(),
    //     config: Some(ContainerConfig{
    //         image: Some(ImageSpec{
    //             image: "quay.io/bpfd-bytecode/xdp_pass:latest".to_string(),
    //             annotations: HashMap::new(),
    //         }),
    //         working_dir: "./".to_string(),
    //         mounts: vec![Mount{
    //             container_path: "/".to_string(),
    //             host_path: "./tmp".to_string(),
    //             readonly: true,
    //             selinux_relabel: false,
    //             propagation: 0
    //         }],
    //         ..Default::default()
    //     }),
    //     sandbox_config: None
    // });
    
    // let response = client
    //      .create_container(request)
    //      .await
    //      .expect("Request failed.");
    // println!("{:?}", response);


}

/// This function will get called on each outbound request. Returning a
/// `Status` here will cancel the request and have that status returned to
/// the caller.
fn intercept(mut req: Request<()>) -> Result<Request<()>, Status> {
    println!("Intercepting request: {:?}", req);
    let md = req.metadata_mut();

    md.insert("containerd-namespace", "moby".parse().unwrap());
    println!("updated request: {:?}", req);

    Ok(req)
}
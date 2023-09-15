// SPDX-License-Identifier: (MIT OR Apache-2.0)
// Copyright Authors of bpfd
use std::collections::HashMap;

use bpfd_api::{
    v1::{
        attach_info::Info, bpfd_server::Bpfd, bytecode_location::Location,
        list_response::ListResult, AttachInfo, BytecodeLocation, GetRequest, GetResponse,
        KernelProgramInfo, KprobeAttachInfo, ListRequest, ListResponse, LoadRequest, LoadResponse,
        ProgramInfo, PullBytecodeRequest, PullBytecodeResponse, TcAttachInfo, TracepointAttachInfo,
        UnloadRequest, UnloadResponse, UprobeAttachInfo, XdpAttachInfo,
    },
    TcProceedOn, XdpProceedOn,
};
use log::warn;
use tokio::sync::{mpsc, mpsc::Sender, oneshot};
use tonic::{Request, Response, Status};

use crate::command::{
    Command, GetArgs, KprobeProgram, LoadArgs, Program, ProgramData, PullBytecodeArgs, TcProgram,
    TracepointProgram, UnloadArgs, UprobeProgram, XdpProgram,
};

#[derive(Debug)]
pub struct BpfdLoader {
    tx: Sender<Command>,
}

impl BpfdLoader {
    pub(crate) fn new(tx: mpsc::Sender<Command>) -> BpfdLoader {
        BpfdLoader { tx }
    }
}

#[tonic::async_trait]
impl Bpfd for BpfdLoader {
    async fn load(&self, request: Request<LoadRequest>) -> Result<Response<LoadResponse>, Status> {
        let request = request.into_inner();

        let (resp_tx, resp_rx) = oneshot::channel();

        if request.attach.is_none() {
            return Err(Status::aborted("missing attach info"));
        }

        if request.bytecode.is_none() {
            return Err(Status::aborted("missing bytecode info"));
        }

        let bytecode_source = match request.bytecode.unwrap().location.unwrap() {
            Location::Image(i) => crate::command::Location::Image(i.into()),
            Location::File(p) => crate::command::Location::File(p),
        };

        let data = ProgramData::new(
            bytecode_source,
            request.name,
            request.metadata,
            request.global_data,
            request.map_owner_id,
        );

        let load_args = LoadArgs {
            program: match request.attach.unwrap().info.unwrap() {
                Info::XdpAttachInfo(XdpAttachInfo {
                    priority,
                    iface,
                    position: _,
                    proceed_on,
                }) => Program::Xdp(XdpProgram::new(
                    data,
                    priority,
                    iface,
                    XdpProceedOn::from_int32s(proceed_on)
                        .map_err(|_| Status::aborted("failed to parse proceed_on"))?,
                )),
                Info::TcAttachInfo(TcAttachInfo {
                    priority,
                    iface,
                    position: _,
                    direction,
                    proceed_on,
                }) => {
                    let direction = direction
                        .try_into()
                        .map_err(|_| Status::aborted("direction is not a string"))?;
                    Program::Tc(TcProgram::new(
                        data,
                        priority,
                        iface,
                        TcProceedOn::from_int32s(proceed_on)
                            .map_err(|_| Status::aborted("failed to parse proceed_on"))?,
                        direction,
                    ))
                }
                Info::TracepointAttachInfo(TracepointAttachInfo { tracepoint }) => {
                    Program::Tracepoint(TracepointProgram::new(data, tracepoint))
                }
                Info::KprobeAttachInfo(KprobeAttachInfo {
                    fn_name,
                    offset,
                    retprobe,
                    namespace,
                }) => Program::Kprobe(KprobeProgram::new(
                    data, fn_name, offset, retprobe, namespace,
                )),
                Info::UprobeAttachInfo(UprobeAttachInfo {
                    fn_name,
                    offset,
                    target,
                    retprobe,
                    pid,
                    namespace,
                }) => Program::Uprobe(UprobeProgram::new(
                    data, fn_name, offset, target, retprobe, pid, namespace,
                )),
            },
            responder: resp_tx,
        };

        // Send the GET request
        self.tx.send(Command::Load(load_args)).await.unwrap();

        // Await the response
        match resp_rx.await {
            Ok(res) => match res {
                Ok(program) => {
                    let reply_entry = LoadResponse {
                        info: convert_to_program_info(&program),
                        kernel_info: convert_to_kernel_info(&program),
                    };
                    Ok(Response::new(reply_entry))
                }
                Err(e) => {
                    warn!("BPFD load error: {:#?}", e);
                    Err(Status::aborted(format!("{e}")))
                }
            },

            Err(e) => {
                warn!("RPC load error: {:#?}", e);
                Err(Status::aborted(format!("{e}")))
            }
        }
    }

    async fn unload(
        &self,
        request: Request<UnloadRequest>,
    ) -> Result<Response<UnloadResponse>, Status> {
        let reply = UnloadResponse {};
        let request = request.into_inner();
        let id = request.id;

        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = Command::Unload(UnloadArgs {
            id,
            responder: resp_tx,
        });

        // Send the GET request
        self.tx.send(cmd).await.unwrap();

        // Await the response
        match resp_rx.await {
            Ok(res) => match res {
                Ok(_) => Ok(Response::new(reply)),
                Err(e) => {
                    warn!("BPFD unload error: {}", e);
                    Err(Status::aborted(format!("{e}")))
                }
            },
            Err(e) => {
                warn!("RPC unload error: {}", e);
                Err(Status::aborted(format!("{e}")))
            }
        }
    }

    async fn get(&self, request: Request<GetRequest>) -> Result<Response<GetResponse>, Status> {
        let request = request.into_inner();
        let id = request.id;

        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = Command::Get(GetArgs {
            id,
            responder: resp_tx,
        });

        let tx = self.tx.lock().unwrap().clone();
        // Send the GET request
        tx.send(cmd).await.unwrap();

        // Await the response
        match resp_rx.await {
            Ok(res) => match res {
                Ok(program) => {
                    let reply_entry = GetResponse {
                        info: convert_to_program_info(&program),
                        kernel_info: convert_to_kernel_info(&program),
                    };
                    Ok(Response::new(reply_entry))
                }
                Err(e) => {
                    warn!("BPFD get error: {}", e);
                    Err(Status::aborted(format!("{e}")))
                }
            },
            Err(e) => {
                warn!("RPC get error: {}", e);
                Err(Status::aborted(format!("{e}")))
            }
        }
    }

    async fn list(&self, request: Request<ListRequest>) -> Result<Response<ListResponse>, Status> {
        let mut reply = ListResponse { results: vec![] };

        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = Command::List { responder: resp_tx };

        // Send the GET request
        self.tx.send(cmd).await.unwrap();

        // Await the response
        match resp_rx.await {
            Ok(res) => match res {
                Ok(results) => {
                    for r in results {
                        // If filtering on Program Type, then make sure this program matches, else skip.
                        if let Some(p) = request.get_ref().program_type {
                            if p != r.kind() as u32 {
                                continue;
                            }
                        }

                        match r.data() {
                            // If filtering on `bpfd Only`, this program is of type Unsupported so skip
                            Err(_) => {
                                if request.get_ref().bpfd_programs_only() {
                                    continue;
                                }
                            }
                            // Bpfd Program
                            Ok(data) => {
                                // Filter on the input metadata field if provided
                                let mut meta_match = true;
                                for (key, value) in &request.get_ref().match_metadata {
                                    if let Some(v) = data.metadata().get(key) {
                                        if *value != *v {
                                            meta_match = false;
                                            break;
                                        }
                                    } else {
                                        meta_match = false;
                                        break;
                                    }
                                }

                                if !meta_match {
                                    continue;
                                }
                            }
                        }

                        // Populate the response with the Program Info and the Kernel Info.
                        let reply_entry = ListResult {
                            info: convert_to_program_info(&r),
                            kernel_info: convert_to_kernel_info(&r),
                        };
                        reply.results.push(reply_entry)
                    }
                    Ok(Response::new(reply))
                }
                Err(e) => {
                    warn!("BPFD list error: {}", e);
                    Err(Status::aborted(format!("{e}")))
                }
            },
            Err(e) => {
                warn!("RPC list error: {}", e);
                Err(Status::aborted(format!("{e}")))
            }
        }
    }

    async fn pull_bytecode(
        &self,
        request: tonic::Request<PullBytecodeRequest>,
    ) -> std::result::Result<tonic::Response<PullBytecodeResponse>, tonic::Status> {
        let request = request.into_inner();
        let image = match request.image {
            Some(i) => i.into(),
            None => return Err(Status::aborted("Empty pull_bytecode request received")),
        };
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = Command::PullBytecode(PullBytecodeArgs {
            image,
            responder: resp_tx,
        });

        self.tx.send(cmd).await.unwrap();

        // Await the response
        match resp_rx.await {
            Ok(res) => match res {
                Ok(_) => {
                    let reply = PullBytecodeResponse {};
                    Ok(Response::new(reply))
                }
                Err(e) => {
                    warn!("BPFD pull_bytecode error: {:#?}", e);
                    Err(Status::aborted(format!("{e}")))
                }
            },

            Err(e) => {
                warn!("RPC pull_bytecode error: {:#?}", e);
                Err(Status::aborted(format!("{e}")))
            }
        }
    }
}

fn convert_to_program_info(program: &Program) -> Option<ProgramInfo> {
    match program.data() {
        // program is of type Unsupported
        Err(_) => None,
        // Bpfd Program
        Ok(data) => {
            let bytecode = match program.location() {
                Some(l) => match l {
                    crate::command::Location::Image(m) => {
                        Some(BytecodeLocation {
                            location: Some(Location::Image(bpfd_api::v1::BytecodeImage {
                                url: m.get_url().to_string(),
                                image_pull_policy: m.get_pull_policy().to_owned() as i32,
                                // Never dump Plaintext Credentials
                                username: Some(String::new()),
                                password: Some(String::new()),
                            })),
                        })
                    }
                    crate::command::Location::File(m) => Some(BytecodeLocation {
                        location: Some(Location::File(m.to_string())),
                    }),
                },
                None => None,
            };

            let attach_info = AttachInfo {
                info: match program.clone() {
                    Program::Xdp(p) => Some(Info::XdpAttachInfo(XdpAttachInfo {
                        priority: p.priority,
                        iface: p.iface,
                        position: p.current_position.unwrap_or(0) as i32,
                        proceed_on: p.proceed_on.as_action_vec(),
                    })),
                    Program::Tc(p) => Some(Info::TcAttachInfo(TcAttachInfo {
                        priority: p.priority,
                        iface: p.iface,
                        position: p.current_position.unwrap_or(0) as i32,
                        direction: p.direction.to_string(),
                        proceed_on: p.proceed_on.as_action_vec(),
                    })),
                    Program::Tracepoint(p) => {
                        Some(Info::TracepointAttachInfo(TracepointAttachInfo {
                            tracepoint: p.tracepoint,
                        }))
                    }
                    Program::Kprobe(p) => Some(Info::KprobeAttachInfo(KprobeAttachInfo {
                        fn_name: p.fn_name,
                        offset: p.offset,
                        retprobe: p.retprobe,
                        namespace: p.namespace,
                    })),
                    Program::Uprobe(p) => Some(Info::UprobeAttachInfo(UprobeAttachInfo {
                        fn_name: p.fn_name,
                        offset: p.offset,
                        target: p.target,
                        retprobe: p.retprobe,
                        pid: p.pid,
                        namespace: p.namespace,
                    })),
                    Program::Unsupported(_) => None,
                },
            };

            // Populate the Program Info with bpfd data
            Some(ProgramInfo {
                name: data.name().to_owned(),
                bytecode,
                attach: Some(attach_info),
                global_data: data.global_data().to_owned(),
                map_owner_id: data.map_owner_id(),
                map_pin_path: data
                    .map_pin_path()
                    .map_or(String::new(), |v| v.to_str().unwrap().to_string()),
                map_used_by: data
                    .maps_used_by()
                    .map_or(vec![], |m| m.iter().map(|m| m.to_string()).collect()),
                metadata: data.metadata().to_owned(),
            })
        }
    }
}

fn convert_to_kernel_info(program: &Program) -> Option<KernelProgramInfo> {
    // Get the Kernel Info.
    let kernel_info = program
        .kernel_info()
        .expect("kernel info should be set for all loaded programs");

    // Populate the Kernel Info.
    Some(KernelProgramInfo {
        id: kernel_info.id,
        name: kernel_info.name.to_owned(),
        program_type: program.kind() as u32,
        loaded_at: kernel_info.loaded_at.to_owned(),
        tag: kernel_info.tag.to_owned(),
        gpl_compatible: kernel_info.gpl_compatible,
        map_ids: kernel_info.map_ids.to_owned(),
        btf_id: kernel_info.btf_id,
        bytes_xlated: kernel_info.bytes_xlated,
        jited: kernel_info.jited,
        bytes_jited: kernel_info.bytes_jited,
        bytes_memlock: kernel_info.bytes_memlock,
        verified_insns: kernel_info.verified_insns,
    })
}

#[cfg(test)]
mod test {
    use bpfd_api::v1::{
        bytecode_location::Location, AttachInfo, BytecodeLocation, LoadRequest, XdpAttachInfo,
    };
    use tokio::sync::mpsc::Receiver;

    use super::*;
    use crate::command::{KernelProgramInfo, Program};

    #[tokio::test]
    async fn test_load_with_valid_id() {
        let (tx, rx) = mpsc::channel(32);
        let loader = BpfdLoader::new(tx.clone());

        let attach_info = AttachInfo {
            info: Some(Info::XdpAttachInfo(XdpAttachInfo {
                iface: "eth0".to_string(),
                priority: 50,
                position: 0,
                proceed_on: vec![2, 31],
            })),
        };
        let request = LoadRequest {
            bytecode: Some(BytecodeLocation {
                location: Some(Location::Image(bpfd_api::v1::BytecodeImage {
                    url: "quay.io/bpfd-bytecode/xdp:latest".to_string(),
                    ..Default::default()
                })),
                ..Default::default()
            }),
            attach: Some(attach_info),
            ..Default::default()
        };

        tokio::spawn(async move {
            mock_serve(rx).await;
        });

        let res = loader.load(Request::new(request)).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_pull_bytecode() {
        let (tx, rx) = mpsc::channel(32);
        let loader = BpfdLoader::new(tx.clone());

        let request = PullBytecodeRequest {
            image: Some(bpfd_api::v1::BytecodeImage {
                url: String::from("quay.io/bpfd-bytecode/xdp_pass:latest"),
                image_pull_policy: bpfd_api::ImagePullPolicy::Always.into(),
                username: Some(String::from("someone")),
                password: Some(String::from("secret")),
            }),
        };

        tokio::spawn(async move { mock_serve(rx).await });

        let res = loader.pull_bytecode(Request::new(request)).await;
        assert!(res.is_ok());
    }

    async fn mock_serve(mut rx: Receiver<Command>) {
        let kernel_info = KernelProgramInfo {
            id: 0,
            name: "".to_string(),
            program_type: 0,
            loaded_at: "".to_string(),
            tag: "".to_string(),
            gpl_compatible: false,
            map_ids: vec![],
            btf_id: 0,
            bytes_xlated: 0,
            jited: false,
            bytes_jited: 0,
            bytes_memlock: 0,
            verified_insns: 0,
        };
        let mut data = ProgramData::default();
        data.set_kernel_info(Some(kernel_info));

        let program = Program::Xdp(XdpProgram {
            data,
            priority: 0,
            if_index: Some(9999),
            iface: String::new(),
            proceed_on: XdpProceedOn::default(),
            current_position: None,
            attached: false,
        });

        while let Some(cmd) = rx.recv().await {
            match cmd {
                Command::Load(args) => args.responder.send(Ok(program.clone())).unwrap(),
                Command::Unload(args) => args.responder.send(Ok(())).unwrap(),
                Command::List { responder, .. } => responder.send(Ok(vec![])).unwrap(),
                Command::Get(args) => args.responder.send(Ok(program.clone())).unwrap(),
                Command::PullBytecode(args) => args.responder.send(Ok(())).unwrap(),
            }
        }
    }
}

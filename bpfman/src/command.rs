// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of bpfman

//! Commands between the RPC thread and the BPF thread
use std::{
    collections::HashMap,
    fmt, fs,
    io::BufReader,
    ops::Deref,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use aya::programs::ProgramInfo as AyaProgInfo;
use bpfman_api::{
    util::directories::{RTDIR_FS, RTDIR_PROGRAMS},
    v1::{
        attach_info::Info, bytecode_location::Location as V1Location, AttachInfo, BytecodeLocation,
        KernelProgramInfo as V1KernelProgramInfo, KprobeAttachInfo, ProgramInfo as V1ProgramInfo,
        TcAttachInfo, TracepointAttachInfo, UprobeAttachInfo, XdpAttachInfo,
    },
    ParseError, ProgramType, TcProceedOn, XdpProceedOn,
};
use chrono::{prelude::DateTime, Local};
use log::info;
use sigstore::crypto::signing_key::kdf;
use sled::Batch;
use tokio::sync::{mpsc::Sender, oneshot};

use crate::{
    errors::BpfmanError,
    multiprog::{DispatcherId, DispatcherInfo},
    oci_utils::image_manager::{BytecodeImage, Command as ImageManagerCommand},
};

/// Provided by the requester and used by the manager task to send
/// the command response back to the requester.
type Responder<T> = oneshot::Sender<T>;

/// Multiple different commands are multiplexed over a single channel.
#[derive(Debug)]
pub(crate) enum Command {
    /// Load a program
    Load(LoadArgs),
    Unload(UnloadArgs),
    List {
        responder: Responder<Result<Vec<Program>, BpfmanError>>,
    },
    Get(GetArgs),
    PullBytecode(PullBytecodeArgs),
}

#[derive(Debug)]
pub(crate) struct LoadArgs {
    pub(crate) program: Program,
    pub(crate) responder: Responder<Result<Program, BpfmanError>>,
}

#[derive(Debug, Clone)]
pub(crate) enum Program {
    Xdp(XdpProgram),
    Tc(TcProgram),
    Tracepoint(TracepointProgram),
    Kprobe(KprobeProgram),
    Uprobe(UprobeProgram),
    Unsupported(KernelProgramInfo),
}

#[derive(Debug)]
pub(crate) struct UnloadArgs {
    pub(crate) id: u32,
    pub(crate) responder: Responder<Result<(), BpfmanError>>,
}

#[derive(Debug)]
pub(crate) struct GetArgs {
    pub(crate) id: u32,
    pub(crate) responder: Responder<Result<Program, BpfmanError>>,
}

#[derive(Debug)]
pub(crate) struct PullBytecodeArgs {
    pub(crate) image: BytecodeImage,
    pub(crate) responder: Responder<Result<(), BpfmanError>>,
}

#[derive(Debug, Clone)]
pub(crate) enum Location {
    Image(BytecodeImage),
    File(String),
}

// TODO astoycos remove this impl, as it's only needed for a hack in the rebuild
// dispatcher code.
impl Default for Location {
    fn default() -> Self {
        Location::File(String::new())
    }
}

impl Location {
    async fn get_program_bytes(
        &self,
        image_manager: Sender<ImageManagerCommand>,
    ) -> Result<(Vec<u8>, String), BpfmanError> {
        match self {
            Location::File(l) => Ok((crate::utils::read(l).await?, "".to_owned())),
            Location::Image(l) => {
                let (tx, rx) = oneshot::channel();
                image_manager
                    .send(ImageManagerCommand::Pull {
                        image: l.image_url.clone(),
                        pull_policy: l.image_pull_policy.clone(),
                        username: l.username.clone(),
                        password: l.password.clone(),
                        resp: tx,
                    })
                    .await
                    .map_err(|e| BpfmanError::RpcSendError(e.into()))?;
                let (path, bpf_function_name) = rx
                    .await
                    .map_err(BpfmanError::RpcRecvError)?
                    .map_err(BpfmanError::BpfBytecodeError)?;

                let (tx, rx) = oneshot::channel();
                image_manager
                    .send(ImageManagerCommand::GetBytecode { path, resp: tx })
                    .await
                    .map_err(|e| BpfmanError::RpcSendError(e.into()))?;

                let bytecode = rx
                    .await
                    .map_err(BpfmanError::RpcRecvError)?
                    .map_err(BpfmanError::BpfBytecodeError)?;

                Ok((bytecode, bpf_function_name))
            }
        }
    }

    pub(crate) fn flatten(&self, id: u32) -> HashMap<&str, sled::IVec> {
        let mut batch: HashMap<&str, sled::IVec> = HashMap::new();
        match self {
            Location::File(l) => batch.insert("{id}_location_filename", l.as_str().into()),
            Location::Image(l) => {
                batch.insert("{id}_location_image_url", l.image_url.as_str().into());
                batch.insert(
                    "{id}_location_image_pull_policy",
                    l.image_pull_policy.to_string().as_str().into(),
                );
                batch.insert(
                    "{id}_location_username",
                    l.username.unwrap_or_default().as_str().into(),
                );
                batch.insert(
                    "{id}_location_password",
                    l.password.unwrap_or_default().as_str().into(),
                )
            }
        };

        batch
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone)]
pub(crate) enum Direction {
    Ingress = 1,
    Egress = 2,
}

impl TryFrom<String> for Direction {
    type Error = ParseError;

    fn try_from(v: String) -> Result<Self, Self::Error> {
        match v.as_str() {
            "ingress" => Ok(Self::Ingress),
            "egress" => Ok(Self::Egress),
            m => Err(ParseError::InvalidDirection {
                direction: m.to_string(),
            }),
        }
    }
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::Ingress => f.write_str("in"),
            Direction::Egress => f.write_str("eg"),
        }
    }
}

// /// KernelProgramInfo stores information about ALL bpf programs loaded
// /// on a system.
// #[derive(Debug, Clone)]
// pub(crate) struct KernelProgramInfo {
//     db_tree: sled::Tree,
//     id: u32,
//     // name: String,
//     // program_type: u32,
//     // loaded_at: String,
//     // tag: String,
//     // gpl_compatible: bool,
//     // map_ids: Vec<u32>,
//     // btf_id: u32,
//     // bytes_xlated: u32,
//     // jited: bool,
//     // bytes_jited: u32,
//     // bytes_memlock: u32,
//     // verified_insns: u32,
// }

// impl KernelProgramInfo {
//     pub(crate) fn get_name(&self) -> Result<&str, BpfmanError> {
//         self.db_tree
//             .get(format!("{}_kernel_info_name", self.id).as_str())
//             .map(|n| std::str::from_utf8(&n.expect("no name found")).unwrap())
//             .map_err(|e| BpfmanError::DatabaseError(format!("Failed to get name"), e.to_string()))
//     }

//     pub(crate) fn get_program_type(&self) -> Result<u32, BpfmanError> {
//         self.db_tree
//             .get(format!("{}_kernel_info_program_type", self.id).as_str())
//             .map(|n| {
//                 u32::from_be_bytes(
//                     n.expect("no program type found")
//                         .to_vec()
//                         .try_into()
//                         .unwrap(),
//                 )
//             })
//             .map_err(|e| {
//                 BpfmanError::DatabaseError(format!("Failed to get program type"), e.to_string())
//             })
//     }

//     pub(crate) fn get_loaded_at(&self) -> Result<String, BpfmanError> {
//         self.db_tree
//             .get(format!("{}_kernel_info_loaded_at", self.id).as_str())
//             .map(|n| {
//                 std::str::from_utf8(&n.expect("no loaded at found"))
//                     .unwrap()
//                     .to_string()
//             })
//             .map_err(|e| {
//                 BpfmanError::DatabaseError(format!("Failed to get loaded at"), e.to_string())
//             })
//     }

//     pub(crate) fn get_tag(&self) -> Result<String, BpfmanError> {
//         self.db_tree
//             .get(format!("{}_kernel_info_tag", self.id).as_str())
//             .map(|n| {
//                 std::str::from_utf8(&n.expect("no tag found"))
//                     .unwrap()
//                     .to_string()
//             })
//             .map_err(|e| BpfmanError::DatabaseError(format!("Failed to get tag"), e.to_string()))
//     }

//     pub(crate) fn get_gpl_compatible(&self) -> Result<bool, BpfmanError> {
//         self.db_tree
//             .get(format!("{}_kernel_info_gpl_compatible", self.id).as_str())
//             .map(|n| {
//                 i8::from_be_bytes(
//                     n.expect("no gpl compatible found")
//                         .to_vec()
//                         .try_into()
//                         .unwrap(),
//                 ) != 0
//             })
//             .map_err(|e| {
//                 BpfmanError::DatabaseError(format!("Failed to get gpl compatible"), e.to_string())
//             })
//     }

//     pub(crate) fn get_map_ids(&self) -> Result<Vec<u32>, BpfmanError> {
//         self.db_tree
//             .scan_prefix(format!("{}_kernel_info_map_ids_", self.id).as_str())
//             .map(|n| n.map(|n| u32::from_be_bytes(n.1.to_vec().try_into().unwrap())))
//             .map(|n| {
//                 n.map_err(|e| {
//                     BpfmanError::DatabaseError(format!("Failed to get map ids"), e.to_string())
//                 })
//             })
//             .collect()
//     }

//     pub(crate) fn get_btf_id(&self) -> Result<u32, BpfmanError> {
//         self.db_tree
//             .get(format!("{}_kernel_info_btf_id", self.id).as_str())
//             .map(|n| {
//                 u32::from_be_bytes(
//                     n.expect("no btf id found")
//                         .to_vec()
//                         .try_into()
//                         .unwrap(),
//                 )
//             })
//             .map_err(|e| {
//                 BpfmanError::DatabaseError(format!("Failed to get btf id"), e.to_string())
//             })
//     }

//     pub(crate) fn get_bytes_xlated(&self) -> Result<u32, BpfmanError> {
//         self.db_tree
//             .get(format!("{}_kernel_info_bytes_xlated", self.id).as_str())
//             .map(|n| {
//                 u32::from_be_bytes(
//                     n.expect("no bytes xlated found")
//                         .to_vec()
//                         .try_into()
//                         .unwrap(),
//                 )
//             })
//             .map_err(|e| {
//                 BpfmanError::DatabaseError(format!("Failed to get bytes xlated"), e.to_string())
//             })
//     }

//     pub(crate) fn get_jited(&self) -> Result<bool, BpfmanError> {
//         self.db_tree
//             .get(format!("{}_kernel_info_jited", self.id).as_str())
//             .map(|n| {
//                 i8::from_be_bytes(
//                     n.expect("no jited found")
//                         .to_vec()
//                         .try_into()
//                         .unwrap(),
//                 ) != 0
//             })
//             .map_err(|e| {
//                 BpfmanError::DatabaseError(format!("Failed to get jited"), e.to_string())
//             })
//     }

//     pub(crate) fn get_bytes_jited(&self) -> Result<u32, BpfmanError> {
//         self.db_tree
//             .get(format!("{}_kernel_info_bytes_jited", self.id).as_str())
//             .map(|n| {
//                 u32::from_be_bytes(
//                     n.expect("no bytes jited found")
//                         .to_vec()
//                         .try_into()
//                         .unwrap(),
//                 )
//             })
//             .map_err(|e| {
//                 BpfmanError::DatabaseError(format!("Failed to get bytes jited"), e.to_string())
//             })
//     }

//     pub(crate) fn get_bytes_memlock(&self) -> Result<u32, BpfmanError> {
//         self.db_tree
//             .get(format!("{}_kernel_info_bytes_memlock", self.id).as_str())
//             .map(|n| {
//                 u32::from_be_bytes(
//                     n.expect("no bytes memlock found")
//                         .to_vec()
//                         .try_into()
//                         .unwrap(),
//                 )
//             })
//             .map_err(|e| {
//                 BpfmanError::DatabaseError(format!("Failed to get bytes memlock"), e.to_string())
//             })
//     }

//     pub(crate) fn get_verified_insns(&self) -> Result<u32, BpfmanError> {
//         self.db_tree
//             .get(format!("{}_kernel_info_verified_insns", self.id).as_str())
//             .map(|n| {
//                 u32::from_be_bytes(
//                     n.expect("no verified insns found")
//                         .to_vec()
//                         .try_into()
//                         .unwrap(),
//                 )
//             })
//             .map_err(|e| {
//                 BpfmanError::DatabaseError(format!("Failed to get verified insns"), e.to_string())
//             })
//     }

//     // load is use to load the KernelProgramInfo from aya into the database.
//     pub(crate) fn load_kernel_info(db_tree: sled::Tree, prog: AyaProgInfo) -> Result<Self, BpfmanError> {
//         let id: u32 = prog.id();

//         db_tree.insert(format!("{id}_kernel_info_id").as_str(), &id.to_be_bytes());
//         db_tree.insert(
//             format!("{id}_kernel_info_name").as_str(),
//             prog.name_as_str().unwrap(),
//         );
//         db_tree.insert(
//             format!("{id}_kernel_info_program_type").as_str(),
//             &prog.program_type().to_be_bytes(),
//         );
//         db_tree.insert(
//             format!("{id}_kernel_info_loaded_at").as_str(),
//             DateTime::<Local>::from(prog.loaded_at())
//                 .format("%Y-%m-%dT%H:%M:%S%z")
//                 .to_string()
//                 .as_str(),
//         );
//         db_tree.insert(
//             format!("{id}_kernel_info_tag").as_str(),
//             format!("{:x}", prog.tag()).as_str(),
//         );
//         db_tree.insert(
//             format!("{id}_kernel_info_gpl_compatible").as_str(),
//             &(prog.gpl_compatible() as i8).to_be_bytes(),
//         );

//         let map_ids = prog
//             .map_ids()
//             .map_err(BpfmanError::BpfProgramError)?
//             .iter()
//             .map(|i| i.to_be_bytes())
//             .collect::<Vec<_>>();

//         map_ids.iter().enumerate().for_each(|(i, v)| {
//             db_tree.insert(format!("{id}_kernel_info_map_ids_{i}").as_str(), v);
//         });

//         db_tree.insert(
//             format!("{id}_kernel_info_btf_id").as_str(),
//             &match prog.btf_id() {
//                 Some(n) => n.get(),
//                 None => 0,
//             }
//             .to_be_bytes(),
//         );
//         db_tree.insert(
//             format!("{id}_kernel_info_bytes_xlated").as_str(),
//             &prog.size_translated().to_be_bytes(),
//         );
//         db_tree.insert(
//             format!("{id}_kernel_info_jited").as_str(),
//             &(prog.size_jitted() % 2).to_be_bytes(),
//         );
//         db_tree.insert(
//             format!("{id}_kernel_info_bytes_jited").as_str(),
//             &prog.size_jitted().to_be_bytes(),
//         );

//         db_tree.insert(
//             format!("{id}_kernel_info_bytes_memlock").as_str(),
//             &prog
//                 .memory_locked()
//                 .map_err(BpfmanError::BpfProgramError)?
//                 .to_be_bytes(),
//         );
//         db_tree.insert(
//             format!("{id}_kernel_info_verified_insns").as_str(),
//             &prog.verified_instruction_count().to_be_bytes(),
//         );

//         Ok(Self { db_tree, id })
//     }
// }

// // impl TryFrom<&Program> for V1ProgramInfo {
// //     type Error = BpfmanError;

// //     fn try_from(program: &Program) -> Result<Self, Self::Error> {
// //         let data = program.data()?;

// //         let bytecode = match program.location() {
// //             Some(l) => match l {
// //                 crate::command::Location::Image(m) => {
// //                     Some(BytecodeLocation {
// //                         location: Some(V1Location::Image(bpfman_api::v1::BytecodeImage {
// //                             url: m.get_url().to_string(),
// //                             image_pull_policy: m.get_pull_policy().to_owned() as i32,
// //                             // Never dump Plaintext Credentials
// //                             username: Some(String::new()),
// //                             password: Some(String::new()),
// //                         })),
// //                     })
// //                 }
// //                 crate::command::Location::File(m) => Some(BytecodeLocation {
// //                     location: Some(V1Location::File(m.to_string())),
// //                 }),
// //             },
// //             None => None,
// //         };

// //         let attach_info = AttachInfo {
// //             info: match program.clone() {
// //                 Program::Xdp(p) => Some(Info::XdpAttachInfo(XdpAttachInfo {
// //                     priority: p.priority,
// //                     iface: p.iface,
// //                     position: p.current_position.unwrap_or(0) as i32,
// //                     proceed_on: p.proceed_on.as_action_vec(),
// //                 })),
// //                 Program::Tc(p) => Some(Info::TcAttachInfo(TcAttachInfo {
// //                     priority: p.priority,
// //                     iface: p.iface,
// //                     position: p.current_position.unwrap_or(0) as i32,
// //                     direction: p.direction.to_string(),
// //                     proceed_on: p.proceed_on.as_action_vec(),
// //                 })),
// //                 Program::Tracepoint(p) => Some(Info::TracepointAttachInfo(TracepointAttachInfo {
// //                     tracepoint: p.tracepoint,
// //                 })),
// //                 Program::Kprobe(p) => Some(Info::KprobeAttachInfo(KprobeAttachInfo {
// //                     fn_name: p.fn_name,
// //                     offset: p.offset,
// //                     retprobe: p.retprobe,
// //                     namespace: p.namespace,
// //                 })),
// //                 Program::Uprobe(p) => Some(Info::UprobeAttachInfo(UprobeAttachInfo {
// //                     fn_name: p.fn_name,
// //                     offset: p.offset,
// //                     target: p.target,
// //                     retprobe: p.retprobe,
// //                     pid: p.pid,
// //                     namespace: p.namespace,
// //                 })),
// //                 Program::Unsupported(_) => None,
// //             },
// //         };

// //         // Populate the Program Info with bpfman data
// //         Ok(V1ProgramInfo {
// //             name: data.name().to_owned(),
// //             bytecode,
// //             attach: Some(attach_info),
// //             global_data: data.global_data().to_owned(),
// //             map_owner_id: data.map_owner_id(),
// //             map_pin_path: data
// //                 .map_pin_path()
// //                 .map_or(String::new(), |v| v.to_str().unwrap().to_string()),
// //             map_used_by: data
// //                 .maps_used_by()
// //                 .map_or(vec![], |m| m.iter().map(|m| m.to_string()).collect()),
// //             metadata: data.metadata().to_owned(),
// //         })
// //     }
// // }

// // impl TryFrom<&Program> for V1KernelProgramInfo {
// //     type Error = BpfmanError;

// //     fn try_from(program: &Program) -> Result<Self, Self::Error> {
// //         // Get the Kernel Info.
// //         let kernel_info = program.kernel_info().ok_or(BpfmanError::Error(
// //             "program kernel info not available".to_string(),
// //         ))?;

// //         // Populate the Kernel Info.
// //         Ok(V1KernelProgramInfo {
// //             id: kernel_info.id,
// //             name: kernel_info.name.to_owned(),
// //             program_type: program.kind() as u32,
// //             loaded_at: kernel_info.loaded_at.to_owned(),
// //             tag: kernel_info.tag.to_owned(),
// //             gpl_compatible: kernel_info.gpl_compatible,
// //             map_ids: kernel_info.map_ids.to_owned(),
// //             btf_id: kernel_info.btf_id,
// //             bytes_xlated: kernel_info.bytes_xlated,
// //             jited: kernel_info.jited,
// //             bytes_jited: kernel_info.bytes_jited,
// //             bytes_memlock: kernel_info.bytes_memlock,
// //             verified_insns: kernel_info.verified_insns,
// //         })
// //     }
// // }

/// ProgramInfo stores information about bpf programs that are loaded and managed
/// by bpfman.
#[derive(Debug, Clone)]
pub(crate) struct ProgramData {
    // known at load time, set by user
    name: String,
    location: Location,
    metadata: HashMap<String, String>,
    global_data: HashMap<String, Vec<u8>>,
    map_owner_id: Option<u32>,
    db_tree: sled::Tree,

    // populated after load
    id: Option<u32>,

    // populated after load
    // kernel_info: Option<KernelProgramInfo>,
    // map_pin_path: Option<PathBuf>,
    // maps_used_by: Option<Vec<u32>>,

    // program_bytes is used to temporarily cache the raw program data during
    // the loading process.  It MUST be cleared following a load so that there
    // is not a long lived copy of the program data living on the heap.
    program_bytes: Vec<u8>,
}

impl ProgramData {
    pub(crate) fn new_pre_id(
        location: Location,
        name: String,
        metadata: HashMap<String, String>,
        global_data: HashMap<String, Vec<u8>>,
        map_owner_id: Option<u32>,
        db_tree: sled::Tree,
    ) -> Self {
        Self {
            name,
            location,
            metadata,
            global_data,
            map_owner_id,
            program_bytes: Vec::new(),
            db_tree,
            id: None, // kernel_info: None,
                      // map_pin_path: None,
                      // maps_used_by: None,
        }
    }

    pub(crate) fn id_unsafe(&self) -> u32 {
        // use as_ref here so we don't consume self.
        self.id.expect("id not set")
    }

    /*
     * Methods for setting and getting kernel information.
     */

    pub(crate) fn get_kernel_name(&self) -> Result<&str, BpfmanError> {
        self.db_tree
            .get(format!("{}_kernel_info_name", self.id_unsafe()).as_str())
            .map(|n| std::str::from_utf8(&n.expect("no name found")).unwrap())
            .map_err(|e| BpfmanError::DatabaseError(format!("Failed to get name"), e.to_string()))
    }

    pub(crate) fn get_kernel_program_type(&self) -> Result<u32, BpfmanError> {
        self.db_tree
            .get(format!("{}_kernel_info_program_type", self.id_unsafe()).as_str())
            .map(|n| bytes_to_u32(n.into()))
            .map_err(|e| {
                BpfmanError::DatabaseError(format!("Failed to get program type"), e.to_string())
            })
    }

    pub(crate) fn get_loaded_at(&self) -> Result<String, BpfmanError> {
        self.db_tree
            .get(format!("{}_kernel_info_loaded_at", self.id_unsafe()).as_str())
            .map(|n| {
                std::str::from_utf8(&n.expect("no loaded at found"))
                    .unwrap()
                    .to_string()
            })
            .map_err(|e| {
                BpfmanError::DatabaseError(format!("Failed to get loaded at"), e.to_string())
            })
    }

    pub(crate) fn get_tag(&self) -> Result<String, BpfmanError> {
        self.db_tree
            .get(format!("{}_kernel_info_tag", self.id_unsafe()).as_str())
            .map(|n| {
                std::str::from_utf8(&n.expect("no tag found"))
                    .unwrap()
                    .to_string()
            })
            .map_err(|e| BpfmanError::DatabaseError(format!("Failed to get tag"), e.to_string()))
    }

    pub(crate) fn get_gpl_compatible(&self) -> Result<bool, BpfmanError> {
        self.db_tree
            .get(format!(
                "{}_kernel_info_gpl_compatible",
                self.id_unsafe().as_str()
            ))
            .map(|n| {
                i8::from_be_bytes(
                    n.expect("no gpl compatible found")
                        .to_vec()
                        .try_into()
                        .unwrap(),
                ) != 0
            })
            .map_err(|e| {
                BpfmanError::DatabaseError(format!("Failed to get gpl compatible"), e.to_string())
            })
    }

    pub(crate) fn get_map_ids(&self) -> Result<Vec<u32>, BpfmanError> {
        self.db_tree
            .scan_prefix(format!("{}_kernel_info_map_ids_", self.id_unsafe()).as_str())
            .map(|n| n.map(|(_, v)| bytes_to_u32(v.into())))
            .map(|n| {
                n.map_err(|e| {
                    BpfmanError::DatabaseError(format!("Failed to get map ids"), e.to_string())
                })
            })
            .collect()
    }

    pub(crate) fn get_btf_id(&self) -> Result<u32, BpfmanError> {
        self.db_tree
            .get(format!("{}_kernel_info_btf_id", self.id_unsafe()).as_str())
            .map(|n| {
                bytes_to_u32(n.into())
            })
            .map_err(|e| BpfmanError::DatabaseError(format!("Failed to get btf id"), e.to_string()))
    }

    pub(crate) fn get_bytes_xlated(&self) -> Result<u32, BpfmanError> {
        self.db_tree
            .get(format!("{}_kernel_info_bytes_xlated", self.id_unsafe()).as_str())
            .map(|n| {
                bytes_to_u32(n.into())
            })
            .map_err(|e| {
                BpfmanError::DatabaseError(format!("Failed to get bytes xlated"), e.to_string())
            })
    }

    pub(crate) fn get_jited(&self) -> Result<bool, BpfmanError> {
        self.db_tree
            .get(format!("{}_kernel_info_jited", self.id_unsafe()).as_str())
            .map(|n| {
                i8::from_be_bytes(n.expect("no jited found").to_vec().try_into().unwrap()) != 0
            })
            .map_err(|e| BpfmanError::DatabaseError(format!("Failed to get jited"), e.to_string()))
    }

    pub(crate) fn get_bytes_jited(&self) -> Result<u32, BpfmanError> {
        self.db_tree
            .get(format!("{}_kernel_info_bytes_jited", self.id_unsafe()).as_str())
            .map(|n| {
                bytes_to_u32(n.into())
            })
            .map_err(|e| {
                BpfmanError::DatabaseError(format!("Failed to get bytes jited"), e.to_string())
            })
    }

    pub(crate) fn get_bytes_memlock(&self) -> Result<u32, BpfmanError> {
        self.db_tree
            .get(format!("{}_kernel_info_bytes_memlock", self.id_unsafe()).as_str())
            .map(|n| {
                bytes_to_u32(n.into())
            })
            .map_err(|e| {
                BpfmanError::DatabaseError(format!("Failed to get bytes memlock"), e.to_string())
            })
    }

    pub(crate) fn get_verified_insns(&self) -> Result<u32, BpfmanError> {
        self.db_tree
            .get(format!("{}_kernel_info_verified_insns", self.id_unsafe()).as_str())
            .map(|n| {
                bytes_to_u32(n.into())
            })
            .map_err(|e| {
                BpfmanError::DatabaseError(format!("Failed to get verified insns"), e.to_string())
            })
    }

    // load is use to load the KernelProgramInfo from aya into the database. Once
    // this function is called all state for a given program will be stored in the
    // database.
    pub(crate) fn load_kernel_info(
        &self,
        db_tree: sled::Tree,
        prog: AyaProgInfo,
    ) -> Result<(), BpfmanError> {
        let id: u32 = prog.id();

        // Load the cached pre_load bpfman_info into the database.
        db_tree.insert(format!("{id}_name").as_str(), self.name.as_str());
        self.location.flatten(id).iter().for_each(|(k, v)| {
            db_tree.insert(k, v);
        });
        self.metadata.iter().for_each(|(k, v)| {
            db_tree
                .insert(format!("{id}_metadata_{k}").as_str(), v.as_str())
                .expect("cannot flatten metadata");
        });
        self.global_data.iter().for_each(|(k, v)| {
            db_tree
                .insert(format!("{id}_global_data_{k}").as_str(), v.deref())
                .expect("cannot flatten global data");
        });
        db_tree.insert(
            format!("{id}_map_owner_id").as_str(),
            &self.map_owner_id.unwrap_or_default().to_be_bytes(),
        );

        // Load the kernel generated information into the database.
        db_tree.insert(format!("{id}_kernel_info_id").as_str(), &id.to_be_bytes());
        db_tree.insert(
            format!("{id}_kernel_info_name").as_str(),
            prog.name_as_str().unwrap(),
        );
        db_tree.insert(
            format!("{id}_kernel_info_program_type").as_str(),
            &prog.program_type().to_be_bytes(),
        );
        db_tree.insert(
            format!("{id}_kernel_info_loaded_at").as_str(),
            DateTime::<Local>::from(prog.loaded_at())
                .format("%Y-%m-%dT%H:%M:%S%z")
                .to_string()
                .as_str(),
        );
        db_tree.insert(
            format!("{id}_kernel_info_tag").as_str(),
            format!("{:x}", prog.tag()).as_str(),
        );
        db_tree.insert(
            format!("{id}_kernel_info_gpl_compatible").as_str(),
            &(prog.gpl_compatible() as i8).to_be_bytes(),
        );

        let map_ids = prog
            .map_ids()
            .map_err(BpfmanError::BpfProgramError)?
            .iter()
            .map(|i| i.to_be_bytes())
            .collect::<Vec<_>>();

        map_ids.iter().enumerate().for_each(|(i, v)| {
            db_tree.insert(format!("{id}_kernel_info_map_ids_{i}").as_str(), v);
        });

        db_tree.insert(
            format!("{id}_kernel_info_btf_id").as_str(),
            &match prog.btf_id() {
                Some(n) => n.get(),
                None => 0,
            }
            .to_be_bytes(),
        );
        db_tree.insert(
            format!("{id}_kernel_info_bytes_xlated").as_str(),
            &prog.size_translated().to_be_bytes(),
        );
        db_tree.insert(
            format!("{id}_kernel_info_jited").as_str(),
            &(prog.size_jitted() % 2).to_be_bytes(),
        );
        db_tree.insert(
            format!("{id}_kernel_info_bytes_jited").as_str(),
            &prog.size_jitted().to_be_bytes(),
        );

        db_tree.insert(
            format!("{id}_kernel_info_bytes_memlock").as_str(),
            &prog
                .memory_locked()
                .map_err(BpfmanError::BpfProgramError)?
                .to_be_bytes(),
        );
        db_tree.insert(
            format!("{id}_kernel_info_verified_insns").as_str(),
            &prog.verified_instruction_count().to_be_bytes(),
        );
        self.id = Some(id);

        Ok(())
    }

    pub(crate) fn set_map_pin_path(&mut self, path: &Path) {
        self.db_tree.insert(
            format!("{}_map_pin_path", self.id_unsafe()).as_str(),
            path.as_os_str().as_bytes(),
        );
    }

    pub(crate) fn get_map_pin_path(&self) -> Result<&Path, BpfmanError> {
        self.db_tree
            .get(format!("{}_map_pin_path", self.id_unsafe()).as_str())
            .map(|n| {
                std::str::from_utf8(&n.expect("no map pin path found"))
                    .unwrap()
                    .to_string()
            })
            .map_err(|e| {
                BpfmanError::DatabaseError(format!("Failed to get map pin path"), e.to_string())
            })
            .map(|n| Path::new(&n))
    }

    pub(crate) fn set_maps_used_by(&self, used_by: Vec<u32>) {
        used_by.iter().enumerate().for_each(|(i, id)| {
            self.db_tree.insert(
                format!("{}_maps_used_by_{}", self.id_unsafe(), i).as_str(),
                &id.to_be_bytes(),
            );
        });
    }

    pub(crate) fn get_maps_used_by(&self) -> Result<Vec<u32>, BpfmanError> {
        self.db_tree
            .scan_prefix(format!("{}_maps_used_by_", self.id_unsafe()).as_str())
            .map(|n| n.map(|(_, v)| u32::from_be_bytes(v.to_vec().try_into().unwrap())))
            .map(|n| {
                n.map_err(|e| {
                    BpfmanError::DatabaseError(format!("Failed to get maps used by"), e.to_string())
                })
            })
            .collect()
    }

    pub(crate) fn get_global_data(&self) -> Result<HashMap<String, Vec<u8>>, BpfmanError> {
        self.db_tree
            .scan_prefix(format!("{}_global_data_", self.id_unsafe()).as_str())
            .map(|n| {
                n.map(|(k, v)| {
                    (
                        std::str::from_utf8(&k)
                            .unwrap()
                            .split("_")
                            .last()
                            .unwrap()
                            .to_string(),
                        v.to_vec(),
                    )
                })
            })
            .map(|n| {
                n.map_err(|e| {
                    BpfmanError::DatabaseError(format!("Failed to get global data"), e.to_string())
                })
            })
            .collect()
    }

    pub(crate) fn get_metadata(&self) -> Result<HashMap<String, String>, BpfmanError> {
        self.db_tree
            .scan_prefix(format!("{}_metadata_", self.id_unsafe()).as_str())
            .map(|n| {
                n.map(|(k, v)| {
                    (
                        std::str::from_utf8(&k)
                            .unwrap()
                            .split("_")
                            .last()
                            .unwrap()
                            .to_string(),
                        std::str::from_utf8(&v).unwrap().to_string(),
                    )
                })
            })
            .map(|n| {
                n.map_err(|e| {
                    BpfmanError::DatabaseError(format!("Failed to get global data"), e.to_string())
                })
            })
            .collect()
    }

    pub(crate) fn get_map_owner_id(&self) -> Result<u32, BpfmanError> {
        self.db_tree
            .get(format!("{}_map_owner_id", self.id_unsafe()).as_str())
            .map(|n| u32::from_be_bytes(&n.expect("no map owner id found")))
            .map_err(|e| {
                BpfmanError::DatabaseError(format!("Failed to get map owner id"), e.to_string())
            })
    }

    // TODO (astoycos)
    pub(crate) fn program_bytes(&self) -> &[u8] {
        &self.program_bytes
    }

    // In order to ensure that the program bytes, which can be a large amount
    // of data is only stored for as long as needed, make sure to call
    // clear_program_bytes following a load.
    pub(crate) fn clear_program_bytes(&mut self) {
        self.program_bytes = Vec::new();
    }

    pub(crate) async fn set_program_bytes(
        &mut self,
        image_manager: Sender<ImageManagerCommand>,
    ) -> Result<(), BpfmanError> {
        match self.location.get_program_bytes(image_manager).await {
            Err(e) => Err(e),
            Ok((v, s)) => {
                match &self.location {
                    Location::Image(l) => {
                        info!(
                            "Loading program bytecode from container image: {}",
                            l.get_url()
                        );
                        // If program name isn't provided and we're loading from a container
                        // image use the program name provided in the image metadata, otherwise
                        // always use the provided program name.
                        let provided_name = self.name.clone();

                        if provided_name.is_empty() {
                            self.name = s;
                        } else if s != provided_name {
                            return Err(BpfmanError::BytecodeMetaDataMismatch {
                                image_prog_name: s,
                                provided_prog_name: provided_name,
                            });
                        }
                    }
                    Location::File(l) => {
                        info!("Loading program bytecode from file: {}", l);
                    }
                }
                self.program_bytes = v;
                Ok(())
            }
        }
    }

    // Flatten the ProgramData structure into a hashmap so that it can be
    // inserted into the sled database. The key will be prefixed with the program's
    // id and generally follow a "id_{field_name}" convention.
    pub(crate) fn flatten(&self, id: u32) -> HashMap<&str, sled::IVec> {
        let mut map: HashMap<&str, sled::IVec> = HashMap::new();
        map.insert(format!("{id}_name").as_str(), self.name.as_str().into());
        map.extend(self.location.flatten(id));
        self.metadata.iter().for_each(|(k, v)| {
            map.insert(format!("{id}_metadata_{k}").as_str(), v.as_str().into())
                .expect("cannot flatten metadata");
        });
        self.global_data.iter().for_each(|(k, v)| {
            map.insert(format!("{id}_global_data_{k}").as_str(), v.deref().into())
                .expect("cannot flatten global data");
        });
        map.insert(
            format!("{id}_map_owner_id").as_str(),
            (&self.map_owner_id.unwrap_or_default().to_be_bytes()).into(),
        );

        map.extend(
            self.kernel_info
                .expect("kernel info should be set after load")
                .flatten(id),
        );

        map.insert(
            format!("{id}_map_pin_path").as_str(),
            self.map_pin_path
                .expect("map pin path should be set after load")
                .as_os_str()
                .to_str()
                .unwrap()
                .into(),
        );

        map.insert(
            format!("{id}_maps_used_by").as_str(),
            format!("{:?}", self.maps_used_by).as_str().into(),
        );

        map
    }
}

#[derive(Debug, Clone)]
pub(crate) struct XdpProgram {
    pub(crate) data: ProgramData,
    // known at load time
    pub(crate) priority: i32,
    pub(crate) iface: String,
    pub(crate) proceed_on: XdpProceedOn,
    // populated after load
    pub(crate) current_position: Option<usize>,
    pub(crate) if_index: Option<u32>,
    pub(crate) attached: bool,
}

impl XdpProgram {
    pub(crate) fn new(
        data: ProgramData,
        priority: i32,
        iface: String,
        proceed_on: XdpProceedOn,
    ) -> Self {
        Self {
            data,
            priority,
            iface,
            proceed_on,
            current_position: None,
            if_index: None,
            attached: false,
        }
    }

    pub(crate) fn flatten(&self, id: u32) -> HashMap<&str, sled::IVec> {
        let mut map: HashMap<&str, sled::IVec> = HashMap::new();

        map.insert(
            format!("{id}_xdp_priority").as_str(),
            (&self.priority.to_be_bytes()).into(),
        );
        map.insert(
            format!("{id}_xdp_iface").as_str(),
            self.iface.as_str().into(),
        );
        map.insert(
            format!("{id}_xdp_proceed_on").as_str(),
            self.proceed_on.to_string().as_str().into(),
        );
        map.insert(
            format!("{id}_xdp_attached").as_str(),
            (&(self.attached as i8).to_be_bytes()).into(),
        );
        map.insert(
            format!("{id}_xdp_current_position").as_str(),
            (&self.current_position.unwrap_or_default().to_be_bytes()).into(),
        );
        map.insert(
            format!("{id}_xdp_if_index").as_str(),
            (&self.if_index.unwrap_or_default().to_be_bytes()).into(),
        );

        map
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TcProgram {
    pub(crate) data: ProgramData,
    // known at load time
    pub(crate) priority: i32,
    pub(crate) iface: String,
    pub(crate) proceed_on: TcProceedOn,
    pub(crate) direction: Direction,
    // populated after load
    pub(crate) current_position: Option<usize>,
    pub(crate) if_index: Option<u32>,
    pub(crate) attached: bool,
}

impl TcProgram {
    pub(crate) fn new(
        data: ProgramData,
        priority: i32,
        iface: String,
        proceed_on: TcProceedOn,
        direction: Direction,
    ) -> Self {
        Self {
            data,
            priority,
            iface,
            proceed_on,
            direction,
            current_position: None,
            if_index: None,
            attached: false,
        }
    }

    pub(crate) fn flatten(&self, id: u32) -> HashMap<&str, sled::IVec> {
        let mut map: HashMap<&str, sled::IVec> = HashMap::new();

        map.insert(
            format!("{id}_tc_priority").as_str(),
            (&self.priority.to_be_bytes()).into(),
        );
        map.insert(
            format!("{id}_tc_iface").as_str(),
            self.iface.as_str().into(),
        );
        map.insert(
            format!("{id}_tc_proceed_on").as_str(),
            self.proceed_on.to_string().as_str().into(),
        );
        map.insert(
            format!("{id}_tc_attached").as_str(),
            (&(self.attached as i8).to_be_bytes()).into(),
        );
        map.insert(
            format!("{id}_tc_current_position").as_str(),
            (&self.current_position.unwrap_or_default().to_be_bytes()).into(),
        );
        map.insert(
            format!("{id}_tc_if_index").as_str(),
            (&self.if_index.unwrap_or_default().to_be_bytes()).into(),
        );
        map.insert(
            format!("{id}_tc_direction").as_str(),
            self.direction.to_string().as_str().into(),
        );

        map
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TracepointProgram {
    pub(crate) data: ProgramData,
    // known at load time
    pub(crate) tracepoint: String,
}

impl TracepointProgram {
    pub(crate) fn new(data: ProgramData, tracepoint: String) -> Self {
        Self { data, tracepoint }
    }

    pub(crate) fn flatten(&self, id: u32) -> HashMap<&str, sled::IVec> {
        let mut map: HashMap<&str, sled::IVec> = HashMap::new();
        map.insert(
            format!("{id}_tracepoint_tracepoint").as_str(),
            self.tracepoint.as_str().into(),
        );
        map
    }
}

#[derive(Debug, Clone)]
pub(crate) struct KprobeProgram {
    pub(crate) data: ProgramData,
    // Known at load time
    pub(crate) fn_name: String,
    pub(crate) offset: u64,
    pub(crate) retprobe: bool,
    pub(crate) namespace: Option<String>,
}

impl KprobeProgram {
    pub(crate) fn new(
        data: ProgramData,
        fn_name: String,
        offset: u64,
        retprobe: bool,
        namespace: Option<String>,
    ) -> Self {
        Self {
            data,
            fn_name,
            offset,
            retprobe,
            namespace,
        }
    }

    pub(crate) fn flatten(&self, id: u32) -> HashMap<&str, sled::IVec> {
        let mut map: HashMap<&str, sled::IVec> = HashMap::new();
        map.insert(
            format!("{id}_kprobe_fn_name").as_str(),
            self.fn_name.as_str().into(),
        );
        map.insert(
            format!("{id}_kprobe_offset").as_str(),
            (&self.offset.to_be_bytes()).into(),
        );
        map.insert(
            format!("{id}_kprobe_retprobe").as_str(),
            (&(self.retprobe as i8).to_be_bytes()).into(),
        );
        map.insert(
            format!("{id}_kprobe_namespace").as_str(),
            self.namespace.unwrap_or_default().as_str().into(),
        );
        map
    }
}

#[derive(Debug, Clone)]
pub(crate) struct UprobeProgram {
    pub(crate) data: ProgramData,
    // Known at load time
    pub(crate) fn_name: Option<String>,
    pub(crate) offset: u64,
    pub(crate) target: String,
    pub(crate) retprobe: bool,
    pub(crate) pid: Option<i32>,
    pub(crate) namespace: Option<String>,
}

impl UprobeProgram {
    pub(crate) fn new(
        data: ProgramData,
        fn_name: Option<String>,
        offset: u64,
        target: String,
        retprobe: bool,
        pid: Option<i32>,
        namespace: Option<String>,
    ) -> Self {
        Self {
            data,
            fn_name,
            offset,
            target,
            retprobe,
            pid,
            namespace,
        }
    }

    pub(crate) fn flatten(&self, id: u32) -> HashMap<&str, sled::IVec> {
        let mut map: HashMap<&str, sled::IVec> = HashMap::new();
        map.insert(
            format!("{id}_uprobe_fn_name").as_str(),
            self.fn_name.unwrap_or_default().as_str().into(),
        );
        map.insert(
            format!("{id}_uprobe_offset").as_str(),
            (&self.offset.to_be_bytes()).into(),
        );
        map.insert(
            format!("{id}_uprobe_retprobe").as_str(),
            (&(self.retprobe as i8).to_be_bytes()).into(),
        );
        map.insert(
            format!("{id}_uprobe_namespace").as_str(),
            self.namespace.unwrap_or_default().as_str().into(),
        );
        map.insert(
            format!("{id}_uprobe_pid").as_str(),
            (&self.pid.unwrap_or_default().to_be_bytes()).into(),
        );
        map.insert(
            format!("{id}_uprobe_target").as_str(),
            self.target.as_str().into(),
        );
        map
    }
}

impl Program {
    pub(crate) fn kind(&self) -> ProgramType {
        match self {
            Program::Xdp(_) => ProgramType::Xdp,
            Program::Tc(_) => ProgramType::Tc,
            Program::Tracepoint(_) => ProgramType::Tracepoint,
            Program::Kprobe(_) => ProgramType::Probe,
            Program::Uprobe(_) => ProgramType::Probe,
            Program::Unsupported(i) => i.program_type.try_into().unwrap(),
        }
    }

    pub(crate) fn dispatcher_id(&self) -> Option<DispatcherId> {
        match self {
            Program::Xdp(p) => Some(DispatcherId::Xdp(DispatcherInfo(
                p.if_index.expect("if_index should be known at this point"),
                None,
            ))),
            Program::Tc(p) => Some(DispatcherId::Tc(DispatcherInfo(
                p.if_index.expect("if_index should be known at this point"),
                Some(p.direction),
            ))),
            _ => None,
        }
    }

    pub(crate) fn data_mut(&mut self) -> Result<&mut ProgramData, BpfmanError> {
        match self {
            Program::Xdp(p) => Ok(&mut p.data),
            Program::Tracepoint(p) => Ok(&mut p.data),
            Program::Tc(p) => Ok(&mut p.data),
            Program::Kprobe(p) => Ok(&mut p.data),
            Program::Uprobe(p) => Ok(&mut p.data),
            Program::Unsupported(_) => Err(BpfmanError::Error(
                "Unsupported program type has no ProgramData".to_string(),
            )),
        }
    }

    pub(crate) fn data(&self) -> Result<&ProgramData, BpfmanError> {
        match self {
            Program::Xdp(p) => Ok(&p.data),
            Program::Tracepoint(p) => Ok(&p.data),
            Program::Tc(p) => Ok(&p.data),
            Program::Kprobe(p) => Ok(&p.data),
            Program::Uprobe(p) => Ok(&p.data),
            Program::Unsupported(_) => Err(BpfmanError::Error(
                "Unsupported program type has no ProgramData".to_string(),
            )),
        }
    }

    pub(crate) fn attached(&self) -> Option<bool> {
        match self {
            Program::Xdp(p) => Some(p.attached),
            Program::Tc(p) => Some(p.attached),
            _ => None,
        }
    }

    pub(crate) fn set_attached(&mut self) {
        match self {
            Program::Xdp(p) => p.attached = true,
            Program::Tc(p) => p.attached = true,
            _ => (),
        }
    }

    pub(crate) fn set_position(&mut self, pos: Option<usize>) {
        match self {
            Program::Xdp(p) => p.current_position = pos,
            Program::Tc(p) => p.current_position = pos,
            _ => (),
        }
    }

    pub(crate) fn kernel_info(&self) -> Option<&KernelProgramInfo> {
        match self {
            Program::Xdp(p) => p.data.kernel_info.as_ref(),
            Program::Tc(p) => p.data.kernel_info.as_ref(),
            Program::Tracepoint(p) => p.data.kernel_info.as_ref(),
            Program::Kprobe(p) => p.data.kernel_info.as_ref(),
            Program::Uprobe(p) => p.data.kernel_info.as_ref(),
            // KernelProgramInfo will never be nil for Unsupported programs
            Program::Unsupported(p) => Some(p),
        }
    }

    // pub(crate) fn save(&self, id: u32) -> Result<(), anyhow::Error> {
    //     let path = format!("{RTDIR_PROGRAMS}/{id}");
    //     serde_json::to_writer(&fs::File::create(path)?, &self)?;
    //     Ok(())
    // }

    // pub(crate) fn delete(&self, id: u32) -> Result<(), anyhow::Error> {
    //     let path = format!("{RTDIR_PROGRAMS}/{id}");
    //     if PathBuf::from(&path).exists() {
    //         fs::remove_file(path)?;
    //     }

    //     let path = format!("{RTDIR_FS}/prog_{id}");
    //     if PathBuf::from(&path).exists() {
    //         fs::remove_file(path)?;
    //     }
    //     let path = format!("{RTDIR_FS}/prog_{id}_link");
    //     if PathBuf::from(&path).exists() {
    //         fs::remove_file(path)?;
    //     }
    //     Ok(())
    // }

    // pub(crate) fn load(id: u32) -> Result<Self, anyhow::Error> {
    //     let path = format!("{RTDIR_PROGRAMS}/{id}");
    //     let file = fs::File::open(path)?;
    //     let reader = BufReader::new(file);
    //     let prog = serde_json::from_reader(reader)?;
    //     Ok(prog)
    // }

    pub(crate) fn if_index(&self) -> Option<u32> {
        match self {
            Program::Xdp(p) => p.if_index,
            Program::Tc(p) => p.if_index,
            _ => None,
        }
    }

    pub(crate) fn set_if_index(&mut self, if_index: u32) {
        match self {
            Program::Xdp(p) => p.if_index = Some(if_index),
            Program::Tc(p) => p.if_index = Some(if_index),
            _ => (),
        }
    }

    pub(crate) fn if_name(&self) -> Option<String> {
        match self {
            Program::Xdp(p) => Some(p.iface.clone()),
            Program::Tc(p) => Some(p.iface.clone()),
            _ => None,
        }
    }

    pub(crate) fn priority(&self) -> Option<i32> {
        match self {
            Program::Xdp(p) => Some(p.priority),
            Program::Tc(p) => Some(p.priority),
            _ => None,
        }
    }

    pub(crate) fn location(&self) -> Option<&Location> {
        match self {
            Program::Xdp(p) => Some(&p.data.location),
            Program::Tracepoint(p) => Some(&p.data.location),
            Program::Tc(p) => Some(&p.data.location),
            Program::Kprobe(p) => Some(&p.data.location),
            Program::Uprobe(p) => Some(&p.data.location),
            Program::Unsupported(_) => None,
        }
    }

    pub(crate) fn direction(&self) -> Option<Direction> {
        match self {
            Program::Tc(p) => Some(p.direction),
            _ => None,
        }
    }

    pub(crate) fn flatten(&self, id: u32) -> Batch {
        let map = match self {
            Program::Xdp(p) => p.flatten(id),
            Program::Tracepoint(p) => p.flatten(id),
            Program::Tc(p) => p.flatten(id),
            Program::Kprobe(p) => p.flatten(id),
            Program::Uprobe(p) => p.flatten(id),
            Program::Unsupported(k) => k.flatten(id),
        };

        let mut batch = sled::Batch::default();

        map.iter().for_each(|(k, v)| {
            batch.insert(*k, *v);
        });

        batch
    }
}

// BpfMap represents a single map pin path used by a Program.  It has to be a
// separate object because its lifetime is slightly different from a Program.
// More specifically a BpfMap can outlive a Program if other Programs are using
// it.
#[derive(Debug, Clone)]
pub(crate) struct BpfMap {
    pub(crate) used_by: Vec<u32>,
}

pub(crate) fn bytes_to_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().unwrap())
}

use std::process::Command;

use assert_cmd::prelude::*;
use log::debug;

use super::{integration_test, IntegrationTest, RTDIR_FS_XDP};
use crate::tests::utils::*;

const NONEXISTENT_UPROBE_IMAGE_LOC: &str = "quay.io/bpfman-bytecode/uprobe_invalid:latest";
const NONEXISTENT_URETPROBE_FILE_LOC: &str =
    "tests/integration-test/bpf/.output/uprobe_invalid.bpf.o";
const INVALID_XDP_IMAGE_LOC: &str = "quay.io//bpfman-bytecode/xdp_pass_invalid:latest";
const INVALID_XDP_FILE_LOC: &str = "tests//integration-test/bpf/.output/xdp_pass_invalid.bpf.o";
const NONEXISTENT_XDP_PASS_NAME: &str = "doesnotexist";
const INVALID_XDP_PASS_NAME: &str = "invalid/interface/%22erwt";
const NONEXISTENT_INTERFACE: &str = "eno1235";
const INVALID_INTERFACE: &str = "invalid/interface/%22erwt";

fn test_bpfmanlist() {
    let args = vec!["list"];

    assert!(!Command::cargo_bin("bpfman")
        .unwrap()
        .args(args)
        .ok()
        .expect("bpfman list failed")
        .stdout
        .is_empty());
}

fn common_load_parameter_testing() {
    for lt in LOAD_TYPES {
        debug!(
            "Error checking common load parameters: non-existent {:?}",
            lt
        );
        let error_prog_id = add_uprobe(
            None, // globals
            lt,
            NONEXISTENT_UPROBE_IMAGE_LOC,
            NONEXISTENT_URETPROBE_FILE_LOC,
            UPROBE_KERNEL_FUNCTION_NAME,
            UPROBE_TARGET,
            None, // container_pid
        );
        assert!(error_prog_id.is_err());
        // Make sure bpfman is still accessible after command
        test_bpfmanlist();
    }

    for lt in LOAD_TYPES {
        debug!("Error checking common load parameters: invalid {:?}", lt);
        let (error_prog_id, _) = add_tc(
            "ingress",
            DEFAULT_BPFMAN_IFACE,
            35,   // priority
            None, // globals
            None, // proceed_on
            lt,
            INVALID_XDP_IMAGE_LOC,
            INVALID_XDP_FILE_LOC,
        );
        assert!(error_prog_id.is_err());
        // Make sure bpfman is still accessible after command
        test_bpfmanlist();
    }

    debug!("Error checking common load parameters: non-existent name");
    let (error_prog_id, _) = add_xdp(
        DEFAULT_BPFMAN_IFACE,
        35,   // priority
        None, // globals
        None, // proceed_on
        &LoadType::File,
        XDP_PASS_IMAGE_LOC,
        XDP_PASS_FILE_LOC,
        NONEXISTENT_XDP_PASS_NAME,
        None, // metadata
        None, // map_owner_id
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();

    debug!("Error checking common load parameters: invalid name");
    let (error_prog_id, _) = add_xdp(
        DEFAULT_BPFMAN_IFACE,
        35,   // priority
        None, // globals
        None, // proceed_on
        &LoadType::File,
        XDP_PASS_IMAGE_LOC,
        XDP_PASS_FILE_LOC,
        INVALID_XDP_PASS_NAME,
        None, // metadata
        None, // map_owner_id
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();

    debug!("Error checking common load parameters: invalid global");
    let invalid_globals = vec!["GLOBAL_u8=61,GLOBAL_u32=0D0C0B0A"];
    let (error_prog_id, _) = add_tracepoint(
        Some(invalid_globals),
        &LoadType::File,
        TRACEPOINT_IMAGE_LOC,
        TRACEPOINT_FILE_LOC,
        TRACEPOINT_TRACEPOINT_NAME,
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();

    debug!("Error checking common load parameters: invalid metadata");
    let key = "invalid metadata";
    let (error_prog_id, _) = add_xdp(
        DEFAULT_BPFMAN_IFACE,
        35,   // priority
        None, // globals
        None, // proceed_on
        &LoadType::File,
        XDP_PASS_IMAGE_LOC,
        XDP_PASS_FILE_LOC,
        XDP_PASS_NAME,
        Some(vec![key]), // metadata
        None,            // map_owner_id
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();

    debug!("Error checking common load parameters: invalid map owner");
    let (error_prog_id, _) = add_xdp(
        DEFAULT_BPFMAN_IFACE,
        INVALID_INTEGER, // priority
        None,            // globals
        None,            // proceed_on
        &LoadType::File,
        XDP_PASS_IMAGE_LOC,
        XDP_PASS_FILE_LOC,
        XDP_PASS_NAME,
        None, // metadata
        None, // map_owner_id
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();
}

fn fentry_load_parameter_testing() {
    debug!("Error checking Fentry load parameters: invalid function name");
    let error_prog_id = add_fentry_or_fexit(
        &LoadType::Image,
        FENTRY_IMAGE_LOC,
        FENTRY_FILE_LOC,
        true, // fentry
        "invalid",
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();
}

fn fexit_load_parameter_testing() {
    debug!("Error checking Fexit load parameters: invalid function name");
    let error_prog_id = add_fentry_or_fexit(
        &LoadType::Image,
        FENTRY_IMAGE_LOC,
        FENTRY_FILE_LOC,
        false, // fentry
        "invalid",
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();
}

fn kprobe_load_parameter_testing() {
    debug!("Error checking kprobe load parameters: invalid function name");
    let error_prog_id = add_kprobe(
        None, // globals
        &LoadType::Image,
        KPROBE_IMAGE_LOC,
        KPROBE_FILE_LOC,
        "invalid", // fn_name
        None, // container_pid
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();

    debug!("Error checking kprobe load parameters: container_pid (not supported)");
    let error_prog_id = add_kprobe(
        None, // globals
        &LoadType::Image,
        KPROBE_IMAGE_LOC,
        KPROBE_FILE_LOC,
        KPROBE_KERNEL_FUNCTION_NAME,
        Some("12345"), // container_pid
    );
    assert!(error_prog_id.is_err());
    debug!("{:?}", error_prog_id.unwrap_err());
    //assert!(error_prog_id.unwrap_err().contains("panic"));
    /*
    RUST_LOG=debug cargo xtask integration-test -- test_invalid_parameters

    [DEBUG integration_test::tests::error] Error checking kprobe load parameters: container_pid (not supported)
    [DEBUG integration_test::tests::error] command="/home/bmcfall/src/bpfman/target/debug/bpfman" "load" "image" "--image-url" "quay.io/bpfman-bytecode/kprobe:latest" "--pull-policy" "Always" "kprobe" "-f" "try_to_wake_up" "--container-pid" "12345"
    code=101
    stdout=""
    stderr=```
    [DEBUG bpfman] Log using env_logger
    [DEBUG sled::pagecache::snapshot] no previous snapshot found
    [DEBUG sled::pagecache::iterator] ordering before clearing tears: {}, max_header_stable_lsn: 0
    [DEBUG sled::pagecache::iterator] in clean_tail_tears, found missing item in tail: None and we\'ll scan segments {} above lowest lsn 0
    [DEBUG sled::pagecache::iterator] unable to load new segment: Io(Custom { kind: Other, error: \"no segments remaining to iterate over\" })
    [DEBUG sled::pagecache::iterator] filtering out segments after detected tear at (lsn, lid) -1
    [DEBUG sled::pagecache::iterator] unable to load new segment: Io(Custom { kind: Other, error: \"no segments remaining to iterate over\" })
    [DEBUG sled::pagecache::segment] SA starting with tip 0 stable -1 free {}
    [DEBUG sled::pagecache::iobuf] starting log for a totally fresh system
    [DEBUG sled::pagecache::segment] segment accountant returning offset: 0 for lsn 0 on deck: {}
    [DEBUG sled::pagecache::iobuf] starting IoBufs with next_lsn: 0 next_lid: 0
    [DEBUG sled::pagecache::iobuf] storing lsn 0 in beginning of buffer
    [DEBUG sled::pagecache] load_snapshot loading pages from 0..0
    [DEBUG sled::meta] allocated pid 3 for root of new_tree [95, 95, 115, 108, 101, 100, 95, 95, 100, 101, 102, 97, 117, 108, 116]
    [DEBUG sled::pagecache::iobuf] advancing offset within the current segment from 0 to 71
    [DEBUG sled::meta] allocated pid 5 for root of new_tree [112, 114, 101, 95, 108, 111, 97, 100, 95, 112, 114, 111, 103, 114, 97, 109, 95, 51, 52, 55, 48, 56, 56, 48, 53, 51, 51]
    [DEBUG sled::pagecache::iobuf] advancing offset within the current segment from 71 to 325
    [DEBUG sled::pagecache::iobuf] wrote lsns 0-70 to disk at offsets 0-70, maxed false complete_len 71
    [DEBUG sled::pagecache::iobuf] mark_interval(0, 71)
    [DEBUG sled::pagecache::iobuf] new highest interval: 0 - 70
    [DEBUG sled::pagecache::iobuf] wrote lsns 71-324 to disk at offsets 71-324, maxed false complete_len 254
    [DEBUG sled::pagecache::iobuf] mark_interval(71, 254)
    [DEBUG sled::pagecache::iobuf] new highest interval: 71 - 324
    [DEBUG sled::pagecache::iobuf] make_stable(324) returning
    thread \'main\' panicked at bpfman/src/bin/cli/load.rs:126:21:
    kprobe container option not supported yet
    note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
    [DEBUG sled::pagecache::logger] IoBufs dropped
    [DEBUG sled::config] removing temporary storage file \"/dev/shm/pagecache.tmp.482414085918488005407116386697216\"
    ```
    */

    // Make sure bpfman is still accessible after command
    test_bpfmanlist();
}

fn kretprobe_load_parameter_testing() {
    debug!("Error checking kretprobe load parameters: invalid function name");
    let error_prog_id = add_kretprobe(
        None, // globals
        &LoadType::Image,
        KRETPROBE_IMAGE_LOC,
        KRETPROBE_FILE_LOC,
        "invalid",
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();
}

fn tc_load_parameter_testing() {
    debug!("Error checking TC load parameters: invalid direction");
    let (error_prog_id, _) = add_tc(
        "invalid",
        NONEXISTENT_INTERFACE,
        35,   // priority
        None, // globals
        None, // proceed_on
        &LoadType::Image,
        TC_PASS_IMAGE_LOC,
        TC_PASS_FILE_LOC,
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();

    debug!("Error checking TC load parameters: non-existent interface");
    let (error_prog_id, _) = add_tc(
        "egress",
        NONEXISTENT_INTERFACE,
        35,   // priority
        None, // globals
        None, // proceed_on
        &LoadType::Image,
        TC_PASS_IMAGE_LOC,
        TC_PASS_FILE_LOC,
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();

    debug!("Error checking TC load parameters: invalid interface");
    let (error_prog_id, _) = add_tc(
        "ingress",
        INVALID_INTERFACE,
        35,   // priority
        None, // globals
        None, // proceed_on
        &LoadType::Image,
        TC_PASS_IMAGE_LOC,
        TC_PASS_FILE_LOC,
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();

    debug!("Error checking TC load parameters: invalid priority");
    let (error_prog_id, _) = add_tc(
        "egress",
        DEFAULT_BPFMAN_IFACE,
        INVALID_INTEGER, // priority
        None,            // globals
        None,            // proceed_on
        &LoadType::File,
        TC_PASS_IMAGE_LOC,
        TC_PASS_FILE_LOC,
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();

    debug!("Error checking TC load parameters: invalid proceed-on");
    let proceed_on = vec!["redirect", "invalid_value"];
    let (error_prog_id, _) = add_tc(
        "ingress",
        DEFAULT_BPFMAN_IFACE,
        35,   // priority
        None, // globals
        Some(proceed_on.clone()),
        &LoadType::File,
        TC_PASS_IMAGE_LOC,
        TC_PASS_FILE_LOC,
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();
}

fn tracepoint_load_parameter_testing() {
    debug!("Error checking tracepoint load parameters: non-existent tracepoint");
    let (error_prog_id, _) = add_tracepoint(
        None, // globals
        &LoadType::Image,
        TRACEPOINT_IMAGE_LOC,
        TRACEPOINT_FILE_LOC,
        "invalid", // tracepoint
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();
}

fn uprobe_load_parameter_testing() {
    debug!("Error checking uprobe load parameters: invalid function name");
    let error_prog_id = add_uprobe(
        None, // globals
        &LoadType::Image,
        UPROBE_IMAGE_LOC,
        UPROBE_FILE_LOC,
        "invalid",
        UPROBE_TARGET,
        None, // container_pid
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();

    debug!("Error checking uprobe load parameters: invalid target");
    let error_prog_id = add_uprobe(
        None, // globals
        &LoadType::Image,
        UPROBE_IMAGE_LOC,
        UPROBE_FILE_LOC,
        UPROBE_KERNEL_FUNCTION_NAME,
        "invalid",
        None, // container_pid
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();

    debug!("Error checking uprobe load parameters: invalid container pid");
    let error_prog_id = add_uprobe(
        None, // globals
        &LoadType::Image,
        UPROBE_IMAGE_LOC,
        UPROBE_FILE_LOC,
        UPROBE_KERNEL_FUNCTION_NAME,
        UPROBE_TARGET,
        Some("invalid"), // container_pid
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();
}

fn uretprobe_load_parameter_testing() {
    debug!("Error checking uretprobe load parameters: invalid function name");
    let error_prog_id = add_uretprobe(
        None, // globals
        &LoadType::Image,
        URETPROBE_IMAGE_LOC,
        URETPROBE_FILE_LOC,
        "invalid",
        None,
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();

    debug!("Error checking uretprobe load parameters: invalid target");
    let error_prog_id = add_uretprobe(
        None, // globals
        &LoadType::Image,
        URETPROBE_IMAGE_LOC,
        URETPROBE_FILE_LOC,
        URETPROBE_FUNCTION_NAME,
        Some("invalid"),
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();
}

fn xdp_load_parameter_testing() {
    debug!("Error checking XDP load parameters: non-existent interface");
    let (error_prog_id, _) = add_xdp(
        NONEXISTENT_INTERFACE,
        35,   // priority
        None, // globals
        None, // proceed_on
        &LoadType::Image,
        XDP_PASS_IMAGE_LOC,
        XDP_PASS_FILE_LOC,
        XDP_PASS_NAME,
        None, // metadata
        None, // map_owner_id
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();

    debug!("Error checking XDP load parameters: invalid interface");
    let (error_prog_id, _) = add_xdp(
        INVALID_INTERFACE,
        35,   // priority
        None, // globals
        None, // proceed_on
        &LoadType::Image,
        XDP_PASS_IMAGE_LOC,
        XDP_PASS_FILE_LOC,
        XDP_PASS_NAME,
        None, // metadata
        None, // map_owner_id
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();

    debug!("Error checking XDP load parameters: invalid priority");
    let (error_prog_id, _) = add_xdp(
        DEFAULT_BPFMAN_IFACE,
        INVALID_INTEGER, // priority
        None,            // globals
        None,            // proceed_on
        &LoadType::File,
        XDP_PASS_IMAGE_LOC,
        XDP_PASS_FILE_LOC,
        XDP_PASS_NAME,
        None, // metadata
        None, // map_owner_id
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();

    debug!("Error checking XDP load parameters: invalid proceed-on");
    let proceed_on = vec!["drop", "invalid_value"];
    let (error_prog_id, _) = add_xdp(
        DEFAULT_BPFMAN_IFACE,
        35,   // priority
        None, // globals
        Some(proceed_on.clone()),
        &LoadType::File,
        XDP_PASS_IMAGE_LOC,
        XDP_PASS_FILE_LOC,
        XDP_PASS_NAME,
        None, // metadata
        None, // map_owner_id
    );
    assert!(error_prog_id.is_err());
    // Make sure bpfman is still accessible after command
    test_bpfmanlist();
}

fn common_get_parameter_testing() {
}
fn common_list_parameter_testing() {
}
fn common_unload_parameter_testing() {
}

#[integration_test]
fn test_invalid_parameters() {
    let _namespace_guard = create_namespace().unwrap();
    let _ping_guard = start_ping().unwrap();

    // Install one set of XDP programs
    assert!(iface_exists(DEFAULT_BPFMAN_IFACE));

    debug!("Installing xdp_pass programs");

    let mut loaded_ids = vec![];

    for lt in LOAD_TYPES {
        let (prog_id, _) = add_xdp(
            DEFAULT_BPFMAN_IFACE,
            35,   // priority
            None, // globals
            None, // proceed_on
            lt,
            XDP_PASS_IMAGE_LOC,
            XDP_PASS_FILE_LOC,
            XDP_PASS_NAME,
            None, // metadata
            None, // map_owner_id
        );
        loaded_ids.push(prog_id.unwrap());

        // Make sure bpfman is still accessible after command
        test_bpfmanlist();
    }
    assert_eq!(loaded_ids.len(), 2);

    assert!(bpffs_has_entries(RTDIR_FS_XDP));

    common_load_parameter_testing();
    fentry_load_parameter_testing();
    fexit_load_parameter_testing();
    kprobe_load_parameter_testing();
    kretprobe_load_parameter_testing();
    tc_load_parameter_testing();
    tracepoint_load_parameter_testing();
    uprobe_load_parameter_testing();
    uretprobe_load_parameter_testing();
    xdp_load_parameter_testing();

    common_get_parameter_testing();
    common_list_parameter_testing();
    common_unload_parameter_testing();

    // Cleanup Installed Programs
    verify_and_delete_programs(loaded_ids);

    assert!(!bpffs_has_entries(RTDIR_FS_XDP));
}

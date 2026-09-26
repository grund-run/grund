use std::{path::PathBuf, time::Duration};

use grund_agent::vm::{Artifact, VmImage, VmRuntime, VmSpec, VmState, metadata};
use grund_vm::{Budget, Config, Firecracker, Network, api::Api, image::file_digest};

const VM_A: &str = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b-vm-a-xxxxxxxxxxxxxxxxxxxxx";
const VM_B: &str = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b-vm-b-xxxxxxxxxxxxxxxxxxxxx";
const GUEST: &str = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b-guest-xxxxxxxxxxxxxxxxxxxx";
const OUT: &str = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b-out-xxxxxxxxxxxxxxxxxxxxxx";
const LAN: &str = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b-lan-xxxxxxxxxxxxxxxxxxxxxx";

struct Artifacts {
    firecracker: PathBuf,
    kernel: PathBuf,
    rootfs: PathBuf,
}

fn artifacts() -> Option<Artifacts> {
    let var = |name: &str| std::env::var_os(name).map(PathBuf::from);
    let found = Artifacts {
        firecracker: var("GRUND_VM_TEST_FIRECRACKER")?,
        kernel: var("GRUND_VM_TEST_KERNEL")?,
        rootfs: var("GRUND_VM_TEST_ROOTFS")?,
    };
    let kvm = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok();
    (kvm && found.firecracker.exists() && found.kernel.exists() && found.rootfs.exists())
        .then_some(found)
}

struct DataDir(PathBuf);

impl Drop for DataDir {
    fn drop(&mut self) {
        let vms = std::fs::read_dir(self.0.join("vms")).into_iter().flatten();
        for vm in vms.flatten() {
            if let Ok(pid) = std::fs::read_to_string(vm.path().join("firecracker.pid")) {
                let _ = std::process::Command::new("kill")
                    .args(["-9", pid.trim()])
                    .status();
            }
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn data_dir() -> DataDir {
    let base = std::env::var_os("GRUND_VM_TEST_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let id = uuid::Uuid::now_v7().simple().to_string();
    DataDir(base.join(format!("grund-vm-{}", &id[20..])))
}

fn runtime(dir: &DataDir, found: &Artifacts) -> Firecracker {
    runtime_on(dir, found, Network::Isolated)
}

fn runtime_on(dir: &DataDir, found: &Artifacts, network: Network) -> Firecracker {
    Firecracker::new(Config {
        data_dir: dir.0.clone(),
        firecracker: found.firecracker.clone(),
        jailer: std::env::var_os("GRUND_VM_TEST_JAILER").map(PathBuf::from),
        network,
        budget: Budget {
            vcpus: 2,
            memory_mib: 1024,
            disk_gib: 4,
        },
    })
    .unwrap()
}

async fn spec(id: &str, found: &Artifacts, vcpus: u32) -> VmSpec {
    spec_for(id, found, vcpus, "https://grund.example.com").await
}

async fn spec_for(id: &str, found: &Artifacts, vcpus: u32, url: &str) -> VmSpec {
    let artifact = |path: &PathBuf, digest: String| Artifact {
        url: format!("file://{}", path.display()),
        sha256: digest,
    };
    VmSpec {
        id: id.into(),
        vcpus,
        memory_mib: 256,
        disk_gib: 1,
        image: VmImage {
            kernel: artifact(&found.kernel, file_digest(&found.kernel).await.unwrap()),
            rootfs: artifact(&found.rootfs, file_digest(&found.rootfs).await.unwrap()),
        },
        mmds: metadata(id, url, "grund_join_test", "later"),
    }
}

async fn until_state(vms: &Firecracker, id: &str, wanted: fn(&VmState) -> bool) -> VmState {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let state = vms
            .observe()
            .await
            .unwrap()
            .into_iter()
            .find(|s| s.id == id)
            .map(|s| s.state)
            .unwrap_or(VmState::Stopped);
        if wanted(&state) || std::time::Instant::now() > deadline {
            return state;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn a_vm_boots_is_ensured_idempotently_is_seen_to_exit_and_is_stopped_with_its_disk() {
    let Some(found) = artifacts() else {
        eprintln!(
            "skipped: needs /dev/kvm and GRUND_VM_TEST_FIRECRACKER, GRUND_VM_TEST_KERNEL, GRUND_VM_TEST_ROOTFS"
        );
        return;
    };
    let dir = data_dir();
    let vms = runtime(&dir, &found);

    let first = spec(VM_A, &found, 1).await;
    let status = vms.ensure(&first).await.unwrap();
    assert_eq!(status.state, VmState::Running, "{status:?}");
    let pid = std::fs::read_to_string(dir.0.join(format!("vms/{VM_A}/firecracker.pid"))).unwrap();
    assert_eq!(vms.ensure(&first).await.unwrap().state, VmState::Running);
    assert_eq!(
        std::fs::read_to_string(dir.0.join(format!("vms/{VM_A}/firecracker.pid"))).unwrap(),
        pid,
        "ensuring a running VM with the same spec starts nothing"
    );
    let recorded = std::fs::read_to_string(dir.0.join(format!("vms/{VM_A}/spec.json"))).unwrap();
    assert!(
        !recorded.contains("grund_join_test"),
        "the token is never written down"
    );

    let too_big = vms.ensure(&spec(VM_B, &found, 2).await).await.unwrap();
    assert_eq!(
        too_big.state,
        VmState::Failed {
            reason: "budget_exceeded: vcpus".into()
        }
    );

    let caps = vms.capabilities().await;
    assert!(caps.kvm && !caps.root && !caps.egress, "{caps:?}");
    assert_eq!(caps.free_vcpus, 1);

    std::process::Command::new("kill")
        .args(["-9", pid.trim()])
        .status()
        .unwrap();
    let exited = until_state(&vms, VM_A, |s| matches!(s, VmState::Exited { .. })).await;
    assert!(matches!(exited, VmState::Exited { .. }), "{exited:?}");
    assert_eq!(
        vms.ensure(&first).await.unwrap().state,
        VmState::Running,
        "an exited VM starts again on its disk"
    );

    vms.stop(VM_A).await.unwrap();
    assert!(
        !dir.0.join("vms/vm-a").exists(),
        "a stopped VM leaves nothing"
    );
    vms.stop(VM_A).await.unwrap();
    let left: Vec<_> = vms
        .observe()
        .await
        .unwrap()
        .into_iter()
        .filter(|s| s.id == VM_A)
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

async fn until_logged(path: &std::path::Path, needle: &str, within: Duration) -> String {
    let deadline = std::time::Instant::now() + within;
    loop {
        let log = std::fs::read_to_string(path).unwrap_or_default();
        if log.contains(needle) || std::time::Instant::now() > deadline {
            return log;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn the_grund_guest_reads_its_assignment_from_the_metadata_and_shuts_down_on_ctrl_alt_del() {
    let (Some(mut found), Some(guest)) = (
        artifacts(),
        std::env::var_os("GRUND_VM_TEST_GUEST_ROOTFS").map(PathBuf::from),
    ) else {
        eprintln!(
            "skipped: also needs GRUND_VM_TEST_GUEST_ROOTFS, an image from crates/grund-guest/build-image.sh"
        );
        return;
    };
    found.rootfs = guest;
    let dir = data_dir();
    let vms = runtime(&dir, &found);
    let status = vms.ensure(&spec(GUEST, &found, 1).await).await.unwrap();
    assert_eq!(status.state, VmState::Running, "{status:?}");
    let console = dir.0.join(format!("vms/{GUEST}/firecracker.log"));

    let log = until_logged(
        &console,
        "could not reach https://grund.example.com",
        Duration::from_secs(30),
    )
    .await;
    assert!(log.contains("grund-guest: started"), "{log}");
    assert!(
        log.contains("grund-guest: grew / to 1024 MiB"),
        "the small image's filesystem fills the VM's 1 GiB disk: {log}"
    );
    assert!(
        log.contains("grund-guest: registering: grund join --mmds"),
        "{log}"
    );
    assert!(
        log.contains("could not reach https://grund.example.com"),
        "grund join found the instance in the metadata and dialled it: {log}"
    );
    assert!(
        !log.contains("grund_join_test"),
        "the token never reaches the console"
    );

    Api::new(vms.api_socket(GUEST))
        .put(
            "/actions",
            &serde_json::json!({ "action_type": "SendCtrlAltDel" }),
        )
        .await
        .unwrap();
    let exited = until_state(&vms, GUEST, |s| matches!(s, VmState::Exited { .. })).await;
    assert!(matches!(exited, VmState::Exited { .. }), "{exited:?}");
    let log = std::fs::read_to_string(&console).unwrap();
    assert!(log.contains("grund-guest: stopping"), "{log}");
    assert!(!log.contains("Kernel panic"), "{log}");
    vms.stop(GUEST).await.unwrap();
}

fn nft_counter(chain: &str, marker: &str) -> u64 {
    let listed = std::process::Command::new("nft")
        .args(["list", "chain", "inet", "grund", chain])
        .output()
        .unwrap();
    String::from_utf8_lossy(&listed.stdout)
        .lines()
        .find(|line| line.contains(marker) && line.contains("counter packets"))
        .and_then(|line| line.split("counter packets ").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

#[tokio::test]
async fn a_bridged_guest_reaches_the_internet_but_not_private_addresses() {
    let (Some(mut found), Some(guest), true) = (
        artifacts(),
        std::env::var_os("GRUND_VM_TEST_GUEST_ROOTFS").map(PathBuf::from),
        std::env::var_os("GRUND_VM_TEST_BRIDGED").is_some() && grund_vm::running_as_root(),
    ) else {
        eprintln!(
            "skipped: needs root, GRUND_VM_TEST_BRIDGED=1 and GRUND_VM_TEST_GUEST_ROOTFS; it sets up grundbr0 and the inet grund table"
        );
        return;
    };
    found.rootfs = guest;
    let private = std::env::var("GRUND_VM_TEST_PRIVATE_URL").unwrap_or("https://10.0.2.2".into());
    let dir = data_dir();
    let vms = runtime_on(&dir, &found, Network::Bridged);
    let caps = vms.capabilities().await;
    assert!(caps.kvm && caps.root && caps.egress, "{caps:?}");
    let dropped_before = nft_counter("forward", "10.0.0.0/8");

    let out = vms
        .ensure(&spec_for(OUT, &found, 1, "https://example.com").await)
        .await
        .unwrap();
    assert_eq!(out.state, VmState::Running, "{out:?}");
    let lan = vms
        .ensure(&spec_for(LAN, &found, 1, &private).await)
        .await
        .unwrap();
    assert_eq!(lan.state, VmState::Running, "{lan:?}");
    let addresses: Vec<String> = [OUT, LAN]
        .iter()
        .map(|id| std::fs::read_to_string(dir.0.join(format!("vms/{id}/address"))).unwrap())
        .collect();
    assert_ne!(addresses[0], addresses[1], "each VM has its own address");
    for (id, address) in [OUT, LAN].iter().zip(&addresses) {
        let pid = std::fs::read_to_string(dir.0.join(format!("vms/{id}/firecracker.pid"))).unwrap();
        let status = std::fs::read_to_string(format!("/proc/{}/status", pid.trim())).unwrap();
        let uid = 1_950_000_000 + address.trim().parse::<u32>().unwrap();
        assert!(
            status.lines().any(|l| l.starts_with("Uid:")
                && l.split_whitespace().skip(1).all(|u| u == uid.to_string())),
            "{id} runs as its own uid {uid}: {status}"
        );
        let root = PathBuf::from(format!("/proc/{}/root", pid.trim()));
        assert!(
            root.join("vmlinux").exists()
                && root.join("fc.sock").exists()
                && !root.join("etc").exists(),
            "{id} sees only its chroot as /"
        );
        if std::env::var_os("GRUND_VM_TEST_CGROUPS").is_some() {
            let cgroup = std::fs::read_to_string(format!("/proc/{}/cgroup", pid.trim())).unwrap();
            let path = cgroup.trim().strip_prefix("0::").unwrap().to_string();
            assert!(
                path.ends_with(&format!("/vms/{}", grund_vm::jail::short(id))),
                "{id} is in its own cgroup: {path}"
            );
            let dir = PathBuf::from("/sys/fs/cgroup").join(path.trim_start_matches('/'));
            let memory = std::fs::read_to_string(dir.join("memory.max")).unwrap();
            assert_eq!(memory.trim(), ((256 + 128) * 1024 * 1024).to_string());
            let cpu = std::fs::read_to_string(dir.join("cpu.max")).unwrap();
            assert_eq!(cpu.trim(), "100000 100000");
        }
    }

    let out_log = until_logged(
        &dir.0.join(format!("vms/{OUT}/firecracker.log")),
        "refused to register this machine",
        Duration::from_secs(60),
    )
    .await;
    assert!(
        out_log.contains("refused to register this machine"),
        "the guest resolved example.com, reached it over TLS and got an answer: {out_log}"
    );
    let lan_log = until_logged(
        &dir.0.join(format!("vms/{LAN}/firecracker.log")),
        "could not reach",
        Duration::from_secs(60),
    )
    .await;
    assert!(lan_log.contains("could not reach"), "{lan_log}");
    assert!(
        nft_counter("forward", "10.0.0.0/8") > dropped_before,
        "the private address was dropped by grund's table"
    );

    vms.stop(OUT).await.unwrap();
    vms.stop(LAN).await.unwrap();
    for address in addresses {
        let tap = format!("/sys/class/net/grundvm{}", address.trim());
        assert!(!std::path::Path::new(&tap).exists(), "{tap} is removed");
    }
}

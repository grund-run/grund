use std::{path::PathBuf, time::Duration};

use grund_agent::vm::{Artifact, VmImage, VmRuntime, VmSpec, VmState, metadata};
use grund_vm::{Budget, Config, Firecracker, Network, image::file_digest};

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

async fn spec(id: &str, found: &Artifacts, vcpus: u32) -> VmSpec {
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
        mmds: metadata(id, "https://grund.example.com", "grund_join_test", "later"),
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
    let base = std::env::var_os("GRUND_VM_TEST_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let id = uuid::Uuid::now_v7().simple().to_string();
    let dir = DataDir(base.join(format!("grund-vm-{}", &id[20..])));
    let vms = Firecracker::new(Config {
        data_dir: dir.0.clone(),
        firecracker: found.firecracker.clone(),
        network: Network::Isolated,
        budget: Budget {
            vcpus: 2,
            memory_mib: 1024,
            disk_gib: 4,
        },
    })
    .unwrap();

    let first = spec("vm-a", &found, 1).await;
    let status = vms.ensure(&first).await.unwrap();
    assert_eq!(status.state, VmState::Running, "{status:?}");
    let pid = std::fs::read_to_string(dir.0.join("vms/vm-a/firecracker.pid")).unwrap();
    assert_eq!(vms.ensure(&first).await.unwrap().state, VmState::Running);
    assert_eq!(
        std::fs::read_to_string(dir.0.join("vms/vm-a/firecracker.pid")).unwrap(),
        pid,
        "ensuring a running VM with the same spec starts nothing"
    );
    let recorded = std::fs::read_to_string(dir.0.join("vms/vm-a/spec.json")).unwrap();
    assert!(
        !recorded.contains("grund_join_test"),
        "the token is never written down"
    );

    let too_big = vms.ensure(&spec("vm-b", &found, 2).await).await.unwrap();
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
    let exited = until_state(&vms, "vm-a", |s| matches!(s, VmState::Exited { .. })).await;
    assert!(matches!(exited, VmState::Exited { .. }), "{exited:?}");
    assert_eq!(
        vms.ensure(&first).await.unwrap().state,
        VmState::Running,
        "an exited VM starts again on its disk"
    );

    vms.stop("vm-a").await.unwrap();
    assert!(
        !dir.0.join("vms/vm-a").exists(),
        "a stopped VM leaves nothing"
    );
    vms.stop("vm-a").await.unwrap();
    let left: Vec<_> = vms
        .observe()
        .await
        .unwrap()
        .into_iter()
        .filter(|s| s.id == "vm-a")
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

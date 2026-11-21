use super::*;
use grund_proto::grund::agent::v1::VolumeMount;

const MACHINE: &str = "11111111-1111-1111-1111-111111111111";
const FLEET: &str = "22222222-2222-2222-2222-222222222222";
const BOOT: &str = "33333333-3333-3333-3333-333333333333";
const APP: &str = "44444444-4444-4444-4444-444444444444";
const IDS: [&str; 2] = [
    "55555555-5555-5555-5555-555555555555",
    "66666666-6666-6666-6666-666666666666",
];

struct Fixture {
    root: PathBuf,
    data: PathBuf,
    fleet: PathBuf,
    attestation: Attestation,
    binds: Vec<VolumeBind>,
}

impl Fixture {
    fn new(count: usize) -> Self {
        let root = std::env::temp_dir().join(format!("grund-carry-{}", Uuid::now_v7()));
        fs::create_dir(&root).unwrap();
        let source = root.join("source");
        let data = root.join("data");
        let fleet = root.join("fleet");
        for path in [&source, &data, &fleet] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for path in [data.join("volumes"), data.join("volume-owners")] {
            fs::create_dir(&path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut entries = Vec::new();
        let mut binds = Vec::new();
        for id in IDS.iter().take(count) {
            let mut bind = prepare(&source, &[], APP, &[mount(id)]).unwrap().remove(0);
            fs::write(
                Path::new(&bind.source).join("database"),
                b"original committed data",
            )
            .unwrap();
            let old = directory(Path::new(&bind.source))
                .unwrap()
                .metadata()
                .unwrap();
            let target = data.join("volumes").join(id);
            fs::create_dir(&target).unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(old.mode() & 0o7777)).unwrap();
            fs::copy(
                Path::new(&bind.source).join("database"),
                target.join("database"),
            )
            .unwrap();
            fs::copy(
                source.join("volume-owners").join(format!("{id}.json")),
                data.join("volume-owners").join(format!("{id}.json")),
            )
            .unwrap();
            let target_fd = directory(&target).unwrap();
            let new = target_fd.metadata().unwrap();
            assert_ne!(old.ino(), new.ino());
            assert_eq!(
                content_digest(&directory(Path::new(&bind.source)).unwrap()).unwrap(),
                content_digest(&target_fd).unwrap()
            );
            entries.push(Entry {
                app_id: APP.into(),
                volume_id: (*id).into(),
                old_device: old.dev(),
                old_inode: old.ino(),
                new_device: new.dev(),
                new_inode: new.ino(),
                content_sha256: content_digest(&target_fd).unwrap(),
            });
            bind.source = target.display().to_string();
            binds.push(bind);
        }
        let original_device = entries[0].old_device;
        let attestation = Attestation {
            version: 1,
            machine_id: MACHINE.into(),
            fleet_machine_id: FLEET.into(),
            placement: 4,
            boot_id: BOOT.into(),
            data_dir: data.clone(),
            device_mapping: DeviceMapping {
                original_device,
                mounted_source_device: original_device,
            },
            entries,
        };
        let fixture = Self {
            root,
            data,
            fleet,
            attestation,
            binds,
        };
        fixture.publish();
        fixture
    }

    fn publish(&self) {
        atomic_json(
            &directory(&self.fleet).unwrap(),
            MANIFEST,
            &self.attestation,
            true,
        )
        .unwrap();
    }

    fn consume(&self) -> anyhow::Result<()> {
        self.consume_with(|_| Ok(()))
    }

    fn consume_with(&self, after: impl FnMut(usize) -> anyhow::Result<()>) -> anyhow::Result<()> {
        consume_at(
            &directory(&self.fleet)?,
            &directory(&self.data)?,
            &ContextBinding {
                machine_id: MACHINE,
                fleet_machine_id: FLEET,
                placement: 4,
                boot_id: BOOT,
                data_dir: &self.data,
            },
            unsafe { libc::geteuid() },
            after,
        )
    }

    fn owner_bytes(&self, index: usize) -> Vec<u8> {
        fs::read(
            self.data
                .join("volume-owners")
                .join(format!("{}.json", IDS[index])),
        )
        .unwrap()
    }

    fn refuses_without_changes(&self) {
        let before: Vec<_> = (0..self.binds.len())
            .map(|index| self.owner_bytes(index))
            .collect();
        assert!(self.consume().is_err());
        for (index, bytes) in before.iter().enumerate() {
            assert_eq!(&self.owner_bytes(index), bytes);
        }
        assert!(!self.fleet.join(CONSUMED).exists());
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn mount(id: &str) -> VolumeMount {
    VolumeMount {
        volume_id: id.into(),
        name: "data".into(),
        path: "/data".into(),
        ..Default::default()
    }
}

#[test]
fn a_verified_carry_rebinds_the_real_volume_without_changing_its_data() {
    let fixture = Fixture::new(1);
    assert!(prepare(&fixture.data, &[], APP, &[mount(IDS[0])]).is_err());
    assert!(verify_bind(&fixture.data, &[], &fixture.binds[0]).is_err());
    fixture.consume().unwrap();
    let bind = prepare(&fixture.data, &[], APP, &[mount(IDS[0])])
        .unwrap()
        .remove(0);
    verify_bind(&fixture.data, &[], &bind).unwrap();
    assert_eq!(
        fs::read(Path::new(&bind.source).join("database")).unwrap(),
        b"original committed data"
    );
    assert!(!fixture.fleet.join(MANIFEST).exists());
    assert!(!fixture.fleet.join(PENDING).exists());
    assert!(fixture.fleet.join(CONSUMED).exists());
    fs::write(
        Path::new(&bind.source).join("database"),
        b"normal writes after durable consumption",
    )
    .unwrap();
    fixture.consume().unwrap();
    verify_bind(&fixture.data, &[], &bind).unwrap();
}

#[test]
fn swapped_and_emptied_copies_never_receive_new_ownership() {
    for swapped in [false, true] {
        let fixture = Fixture::new(1);
        let path = Path::new(&fixture.binds[0].source);
        if swapped {
            fs::rename(path, fixture.root.join("retained-copy")).unwrap();
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(path.join("database"), b"original committed data").unwrap();
        } else {
            fs::remove_file(path.join("database")).unwrap();
        }
        fixture.refuses_without_changes();
        assert!(prepare(&fixture.data, &[], APP, &[mount(IDS[0])]).is_err());
        assert!(verify_bind(&fixture.data, &[], &fixture.binds[0]).is_err());
    }
}

#[test]
fn invalid_proof_context_and_owner_transitions_are_refused_before_any_update() {
    let changes: [fn(&mut Attestation); 14] = [
        |a| a.version = 2,
        |a| a.machine_id = FLEET.into(),
        |a| a.fleet_machine_id = MACHINE.into(),
        |a| a.placement += 1,
        |a| a.boot_id = MACHINE.into(),
        |a| a.data_dir = PathBuf::from("/unrelated"),
        |a| a.device_mapping.original_device += 1,
        |a| a.device_mapping.mounted_source_device = 0,
        |a| a.entries[1].old_inode += 1,
        |a| a.entries[1].app_id = MACHINE.into(),
        |a| a.entries[1].volume_id = MACHINE.into(),
        |a| a.entries[1].new_inode += 1,
        |a| a.entries[1].content_sha256 = "0".repeat(64),
        |a| a.entries.push(a.entries[0].clone()),
    ];
    for change in changes {
        let mut fixture = Fixture::new(2);
        change(&mut fixture.attestation);
        fixture.publish();
        fixture.refuses_without_changes();
        assert!(prepare(&fixture.data, &[], APP, &[mount(IDS[0])]).is_err());
    }
    let fixture = Fixture::new(2);
    let owners = directory(&fixture.data.join("volume-owners")).unwrap();
    let mut owner: Owner = read_private(&owners, &format!("{}.json", IDS[1]), unsafe {
        libc::geteuid()
    })
    .unwrap()
    .unwrap();
    owner.deleting = true;
    atomic_json(&owners, &format!("{}.json", IDS[1]), &owner, true).unwrap();
    fixture.refuses_without_changes();
}

#[test]
fn incomplete_inventories_and_oversized_or_unknown_metadata_are_refused() {
    let mut fixture = Fixture::new(2);
    fixture.attestation.entries.pop();
    fixture.publish();
    fixture.refuses_without_changes();
    let fixture = Fixture::new(1);
    let path = fixture.fleet.join(MANIFEST);
    fs::write(&path, vec![b' '; MAX_BYTES + 1]).unwrap();
    fixture.refuses_without_changes();
    let fixture = Fixture::new(1);
    let mut json = serde_json::to_value(&fixture.attestation).unwrap();
    json["unrecognized"] = true.into();
    atomic_json(&directory(&fixture.fleet).unwrap(), MANIFEST, &json, true).unwrap();
    fixture.refuses_without_changes();
}

#[test]
fn symlink_hardlink_and_public_metadata_cannot_authorize_a_carry() {
    for owner_record in [false, true] {
        for attack in 0..3 {
            let fixture = Fixture::new(1);
            let path = if owner_record {
                fixture
                    .data
                    .join("volume-owners")
                    .join(format!("{}.json", IDS[0]))
            } else {
                fixture.fleet.join(MANIFEST)
            };
            let retained = fixture.root.join("retained-metadata");
            match attack {
                0 => {
                    fs::rename(&path, &retained).unwrap();
                    std::os::unix::fs::symlink(&retained, &path).unwrap();
                }
                1 => fs::hard_link(&path, &retained).unwrap(),
                _ => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            }
            fixture.refuses_without_changes();
        }
    }
}

#[test]
fn partial_consumption_resumes_only_the_identical_mapping_after_rechecking_all_content() {
    let fixture = Fixture::new(2);
    assert!(
        fixture
            .consume_with(|index| {
                ensure!(
                    index != 0,
                    "simulated process loss after first durable owner"
                );
                Ok(())
            })
            .is_err()
    );
    assert!(fixture.fleet.join(PENDING).exists());
    assert!(!fixture.fleet.join(CONSUMED).exists());
    verify_bind(&fixture.data, &[], &fixture.binds[0]).unwrap();
    assert!(verify_bind(&fixture.data, &[], &fixture.binds[1]).is_err());
    fixture.consume().unwrap();
    for bind in &fixture.binds {
        verify_bind(&fixture.data, &[], bind).unwrap();
    }

    let mut fixture = Fixture::new(2);
    assert!(
        fixture
            .consume_with(|_| anyhow::bail!("simulated crash"))
            .is_err()
    );
    fixture.attestation.entries[1].old_inode += 1;
    fixture.publish();
    fixture.refuses_without_changes();

    let fixture = Fixture::new(2);
    assert!(
        fixture
            .consume_with(|_| anyhow::bail!("simulated crash"))
            .is_err()
    );
    fs::remove_file(Path::new(&fixture.binds[0].source).join("database")).unwrap();
    fixture.refuses_without_changes();
}

#[test]
fn a_consumed_receipt_never_authorizes_a_replacement_or_replayed_manifest() {
    for replay in [false, true] {
        let fixture = Fixture::new(1);
        fixture.consume().unwrap();
        let path = Path::new(&fixture.binds[0].source);
        fs::rename(path, fixture.root.join("retained-data")).unwrap();
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        if replay {
            fs::rename(fixture.fleet.join(CONSUMED), fixture.fleet.join(MANIFEST)).unwrap();
        }
        assert!(fixture.consume().is_err());
        assert!(prepare(&fixture.data, &[], APP, &[mount(IDS[0])]).is_err());
        assert!(verify_bind(&fixture.data, &[], &fixture.binds[0]).is_err());
        assert_eq!(
            fs::read(fixture.root.join("retained-data/database")).unwrap(),
            b"original committed data"
        );
    }
}

#[test]
fn a_previous_boot_receipt_is_not_an_authorization_on_the_current_boot() {
    let mut fixture = Fixture::new(1);
    fixture.consume().unwrap();
    fixture.attestation.boot_id = MACHINE.into();
    atomic_json(
        &directory(&fixture.fleet).unwrap(),
        CONSUMED,
        &fixture.attestation,
        true,
    )
    .unwrap();
    let path = Path::new(&fixture.binds[0].source);
    fs::rename(path, fixture.root.join("retained-data")).unwrap();
    fs::create_dir(path).unwrap();
    fixture.consume().unwrap();
    assert!(prepare(&fixture.data, &[], APP, &[mount(IDS[0])]).is_err());
}

#[test]
#[ignore = "requires root; run the carry suite as root with --include-ignored"]
fn container_owned_volume_roots_are_hashed_without_requiring_root_ownership() {
    let fixture = Fixture::new(1);
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "this regression requires root"
    );
    let path = CString::new(fixture.binds[0].source.as_bytes()).unwrap();
    assert_eq!(unsafe { libc::chown(path.as_ptr(), 999, 999) }, 0);
    let mut fixture = fixture;
    fixture.attestation.entries[0].content_sha256 =
        content_digest(&directory(Path::new(&fixture.binds[0].source)).unwrap()).unwrap();
    fixture.publish();
    fixture.consume().unwrap();
    verify_bind(&fixture.data, &[], &fixture.binds[0]).unwrap();
    assert_eq!(
        directory(Path::new(&fixture.binds[0].source))
            .unwrap()
            .metadata()
            .unwrap()
            .uid(),
        999
    );
}

#[test]
fn an_empty_inventory_never_creates_volume_directories_or_accepts_a_half_missing_registry() {
    for missing_both in [false, true] {
        let mut fixture = Fixture::new(1);
        fs::remove_dir_all(fixture.data.join("volumes")).unwrap();
        if missing_both {
            fs::remove_dir_all(fixture.data.join("volume-owners")).unwrap();
        }
        fixture.attestation.entries.clear();
        fixture.publish();
        if missing_both {
            fixture.consume().unwrap();
            assert!(!fixture.data.join("volumes").exists());
            assert!(!fixture.data.join("volume-owners").exists());
        } else {
            assert!(fixture.consume().is_err());
            assert!(!fixture.fleet.join(PENDING).exists());
        }
    }
}

#[test]
fn no_manifest_keeps_the_ordinary_volume_guards_without_creating_a_handoff() {
    let fixture = Fixture::new(1);
    fs::remove_file(fixture.fleet.join(MANIFEST)).unwrap();
    let before = fixture.owner_bytes(0);
    fixture.consume().unwrap();
    assert_eq!(fixture.owner_bytes(0), before);
    assert!(prepare(&fixture.data, &[], APP, &[mount(IDS[0])]).is_err());
    assert!(!fixture.fleet.join(PENDING).exists());
    assert!(!fixture.fleet.join(CONSUMED).exists());
}

#[test]
fn carried_content_hashes_raw_names_and_symlinks_without_following_them() {
    use std::os::unix::ffi::OsStringExt;
    let fixture = Fixture::new(1);
    let root = Path::new(&fixture.binds[0].source);
    let raw_name = OsString::from_vec(vec![0xff, b'z']);
    fs::write(root.join(&raw_name), b"binary name").unwrap();
    let outside = fixture.root.join("outside");
    fs::write(&outside, b"not part of the volume").unwrap();
    std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
    let dir = directory(root).unwrap();
    let before = content_digest(&dir).unwrap();
    fs::write(&outside, b"outside bytes are not followed").unwrap();
    assert_eq!(content_digest(&dir).unwrap(), before);
    fs::remove_file(root.join("link")).unwrap();
    std::os::unix::fs::symlink("different-target", root.join("link")).unwrap();
    assert_ne!(content_digest(&dir).unwrap(), before);
    let before = content_digest(&dir).unwrap();
    fs::set_permissions(root.join(&raw_name), fs::Permissions::from_mode(0o640)).unwrap();
    assert_ne!(content_digest(&dir).unwrap(), before);
    let fifo = CString::new(root.join("fifo").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(content_digest(&dir).is_err());
}

#[test]
fn writable_metadata_parents_and_symlinked_registries_refuse_before_updates() {
    for symlinked in [false, true] {
        let fixture = Fixture::new(1);
        let registry = fixture.data.join("volume-owners");
        if symlinked {
            let retained = fixture.root.join("retained-registry");
            fs::rename(&registry, &retained).unwrap();
            std::os::unix::fs::symlink(&retained, &registry).unwrap();
        } else {
            fs::set_permissions(&registry, fs::Permissions::from_mode(0o777)).unwrap();
        }
        fixture.refuses_without_changes();
    }
}

#[test]
fn a_crash_after_durable_receipt_publication_finishes_journal_cleanup_without_rehashing() {
    let fixture = Fixture::new(1);
    fixture.consume().unwrap();
    atomic_json(
        &directory(&fixture.fleet).unwrap(),
        PENDING,
        &fixture.attestation,
        false,
    )
    .unwrap();
    fs::write(
        Path::new(&fixture.binds[0].source).join("database"),
        b"normal post-consumption write",
    )
    .unwrap();
    fixture.consume().unwrap();
    assert!(!fixture.fleet.join(PENDING).exists());
    verify_bind(&fixture.data, &[], &fixture.binds[0]).unwrap();
}

#[test]
fn an_exact_attestation_of_a_legitimately_empty_original_is_not_a_replacement() {
    let mut fixture = Fixture::new(1);
    fs::remove_file(
        fixture
            .root
            .join("source/volumes")
            .join(IDS[0])
            .join("database"),
    )
    .unwrap();
    fs::remove_file(Path::new(&fixture.binds[0].source).join("database")).unwrap();
    fixture.attestation.entries[0].content_sha256 =
        content_digest(&directory(Path::new(&fixture.binds[0].source)).unwrap()).unwrap();
    fixture.publish();
    fixture.consume().unwrap();
    let bind = prepare(&fixture.data, &[], APP, &[mount(IDS[0])])
        .unwrap()
        .remove(0);
    verify_bind(&fixture.data, &[], &bind).unwrap();
    assert_eq!(fs::read_dir(&bind.source).unwrap().count(), 0);
}

#[test]
#[ignore = "requires root; run the carry suite as root with --include-ignored"]
fn the_real_digest_matches_the_shared_fleet_contract_vector() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "this contract vector requires root"
    );
    let fixture = Fixture::new(1);
    let root = Path::new(&fixture.binds[0].source);
    fs::remove_file(root.join("database")).unwrap();
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.join("PG_VERSION"), b"18\n").unwrap();
    fs::set_permissions(root.join("PG_VERSION"), fs::Permissions::from_mode(0o644)).unwrap();
    for path in [root.to_path_buf(), root.join("PG_VERSION")] {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(path.as_ptr(), 70, 70) }, 0);
    }
    assert_eq!(
        content_digest(&directory(root).unwrap()).unwrap(),
        "ee763c0069c5ba26cfef61791d805de435aa99fde921fe4ddeeafd5cfe7fe0e1"
    );
}

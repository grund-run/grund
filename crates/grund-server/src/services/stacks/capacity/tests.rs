use super::*;

fn service(id: u128, memory: u64, cpu: u32, exclusive: bool) -> Service {
    let declared =
        grund_config::app::file::parse_app("apps:\n  web:\n    image: nginx:1\n", "web").unwrap();
    let mut spec = declared.spec;
    spec.memory_mib = memory;
    spec.cpu_millis = cpu;
    let mut settings = grund_config::app::spec::AppSettings::validate(declared.settings).unwrap();
    settings.copies = 1;
    settings.rollout.max_surge = 1;
    settings.rollout.max_unavailable = 0;
    Service {
        app_id: Uuid::from_u128(id),
        app_name: format!("backing{id}"),
        release: Release {
            number: 1,
            spec,
            image_digest: format!("sha256:{}", "a".repeat(64)),
            platforms: vec![],
            exposed_ports: None,
            secret_versions: vec![],
            source: ReleaseSource::File,
            rollback_of: None,
            note: String::new(),
            created_by: Uuid::nil(),
            created_at: Utc::now(),
            external_release: None,
            request: None,
        },
        settings,
        depends_on: vec![],
        exclusive,
        template: None,
    }
}

fn revision(services: &[(&str, Service)]) -> Revision {
    Revision {
        number: 1,
        yaml: String::new(),
        services: services
            .iter()
            .map(|(name, value)| ((*name).into(), value.clone()))
            .collect(),
        public_service: None,
        public_port: None,
        created_at: Utc::now(),
        created_by: Uuid::nil(),
        rollback_of: None,
    }
}

fn state(revision: &Revision, kind: Kind, names: &[&str]) -> Stack {
    Stack {
        exists: true,
        organisation_id: Uuid::from_u128(10),
        name: "shop".into(),
        revisions: BTreeMap::from([(revision.number, revision.clone())]),
        desired_revision: revision.number,
        operation: Some(operation(
            kind,
            revision.number,
            0,
            names.iter().map(|name| (*name).into()).collect(),
            Utc::now(),
        )),
        ..Default::default()
    }
}

#[test]
fn an_already_created_initial_target_does_not_reserve_a_phantom_second_copy() {
    let revision = revision(&[
        ("producer", service(1, 1536, 100, false)),
        ("consumer", service(2, 128, 200, true)),
    ]);
    let mut previous = state(&revision, Kind::Deploy, &["producer", "consumer"]);
    previous
        .operation
        .as_mut()
        .unwrap()
        .releases
        .insert("producer".into(), 1);
    assert_eq!(
        reservation(
            &revision,
            Some(&previous),
            &[(Uuid::from_u128(1), 1536, 100, 1)]
        )
        .unwrap(),
        (1664, 300)
    );
}

#[test]
fn a_restart_reserves_surge_before_the_next_child_release_number_is_committed() {
    let revision = revision(&[("web", service(1, 512, 100, false))]);
    let previous = state(&revision, Kind::Restart, &["web"]);
    assert_eq!(
        reservation(
            &revision,
            Some(&previous),
            &[(Uuid::from_u128(1), 512, 100, 1)]
        )
        .unwrap(),
        (1024, 200)
    );
}

#[test]
fn serial_updates_reserve_the_largest_transition_not_every_services_surge() {
    let mut producer = service(1, 512, 200, false);
    producer.release.number = 2;
    let mut consumer = service(2, 256, 300, true);
    consumer.release.number = 2;
    let revision = revision(&[("producer", producer), ("consumer", consumer)]);
    let previous = state(&revision, Kind::Deploy, &["producer", "consumer"]);
    let live = [
        (Uuid::from_u128(1), 1536, 100, 1),
        (Uuid::from_u128(2), 128, 200, 1),
    ];
    assert_eq!(
        reservation(&revision, Some(&previous), &live).unwrap(),
        (2176, 500)
    );
}

#[test]
fn a_removed_service_releases_its_budget_before_the_next_serial_start() {
    let old = revision(&[("old", service(1, 1024, 400, false))]);
    let mut revision = revision(&[("new", service(2, 256, 100, false))]);
    revision.number = 2;
    let mut previous = state(&revision, Kind::Deploy, &["old", "new"]);
    previous.revisions.insert(1, old);
    assert_eq!(
        reservation(
            &revision,
            Some(&previous),
            &[(Uuid::from_u128(1), 1024, 400, 1)]
        )
        .unwrap(),
        (1024, 400)
    );
}

#[test]
fn unchanged_dependencies_still_reserve_replacement_capacity_when_their_copies_are_missing() {
    let revision = revision(&[
        ("producer", service(1, 512, 100, false)),
        ("consumer", service(2, 128, 200, true)),
    ]);
    let previous = state(&revision, Kind::Restart, &["producer"]);
    assert_eq!(
        reservation(
            &revision,
            Some(&previous),
            &[(Uuid::from_u128(1), 512, 100, 1)]
        )
        .unwrap(),
        (1152, 400)
    );
}

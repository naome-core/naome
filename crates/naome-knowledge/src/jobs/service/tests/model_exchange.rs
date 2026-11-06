use super::*;
use crate::learning::{Blob, model::Checkpoint};
use crate::model_exchange::{Bundle, Model, Registration};

#[test]
fn solver_selection_replays_atomically_after_an_uncertain_commit() {
    let directory = Directory::new();
    let settings = Settings {
        native_proof_learning: true,
        ..Settings::default()
    };
    let (mut disk, mut journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let current = disk.solver_snapshot(&journal).unwrap().registration;
    // Storage-level fault injection. The reference engine checks native
    // serialization and both artifacts at the independently tested boundary.
    let model = b"paired model".to_vec();
    let adam = b"paired optimizer".to_vec();
    let registration = Registration::new(Model::Solver {
        checkpoint: Checkpoint {
            updates: 1,
            model: Some(Blob::of(&model)),
            optimizer: Some(Blob::of(&adam)),
            ..Checkpoint::fresh()
        },
    });
    let memory = Bundle::reserve(&registration).unwrap();
    let bundle = Arc::new(Bundle::new(registration.clone(), vec![model, adam], memory).unwrap());

    crate::checkpoint::fail_next_commit();
    let unwritten = disk.select_solver(&mut journal, &current.id(), Some(bundle.clone()));
    assert!(matches!(unwritten, Err(crate::Error::ExecutionLimit)));
    assert_eq!(
        disk.solver_snapshot(&journal).unwrap().registration,
        current
    );

    crate::checkpoint::fail_after_commit();
    let uncertain = disk.select_solver(&mut journal, &current.id(), Some(bundle.clone()));
    assert!(matches!(
        uncertain,
        Err(crate::Error::UncertainDurability(_))
    ));
    assert_eq!(
        journal.learning.unwrap().exchange_model(),
        match &current.model {
            Model::Solver { checkpoint } => checkpoint,
            _ => unreachable!(),
        }
    );
    drop(disk);
    let (mut disk, mut journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let recovered = disk.solver_snapshot(&journal).unwrap();
    assert_eq!(recovered.registration, registration);
    for blob in registration.model.blobs() {
        assert_eq!(recovered.part(blob), bundle.part(blob));
    }
    assert!(
        disk.select_solver(&mut journal, &current.id(), Some(bundle))
            .is_err()
    );
    assert_eq!(
        disk.select_solver(&mut journal, &registration.id(), None)
            .unwrap(),
        current
    );
    drop(disk);
    let (disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    assert_eq!(
        disk.solver_snapshot(&journal).unwrap().registration,
        current
    );
}

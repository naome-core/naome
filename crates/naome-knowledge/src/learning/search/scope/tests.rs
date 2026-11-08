use super::*;

#[test]
fn scoped_program_applies_two_premises_in_one_checked_action() {
    struct NoModel;
    impl Ranker for NoModel {
        fn scores(&mut self, _: &Decision) -> Result<Vec<f32>, String> {
            Err("the applicable action closes without ranking".into())
        }
    }

    let [x, y, z] = [0, 1, 2].map(FreeVariable::new);
    let rule = Formula::for_all(
        y,
        Formula::implies(
            Formula::member(y, x),
            Formula::implies(Formula::equal(y, z), Formula::member(x, y)),
        ),
    );
    let target = Formula::for_all(
        x,
        Formula::for_all(
            z,
            Formula::implies(
                rule,
                Formula::implies(
                    Formula::member(z, x),
                    Formula::implies(Formula::equal(z, z), Formula::member(x, z)),
                ),
            ),
        ),
    );
    let (tree, work) = search(&target, &mut NoModel, 1, Instant::now()).unwrap();
    assert_eq!(work, 1);
    let Some(Tree::Scoped { actions, .. }) = tree else {
        panic!("the compound action must close the goal");
    };
    assert!(
        matches!(&actions[..], [ScopedAction::Instantiate { premises, .. }] if premises.len() == 2)
    );
    let commands = commands(&target, &actions).unwrap();
    let mut checker =
        naome_checker::program::Engine::open(rusqlite::Connection::open_in_memory().unwrap())
            .unwrap();
    checker.append_group(&commands).unwrap();
    while checker
        .advance(64, 32768, &naome_checker::ArtifactState::new())
        .unwrap()
    {}
    while !checker.prepare_export(64).unwrap() {}
    assert_eq!(checker.checked().unwrap().conclusion(), Some(&target));
}

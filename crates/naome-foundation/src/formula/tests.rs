use super::{Formula, FreeVariable, Node, Variable, bind_free};

#[test]
#[should_panic(expected = "formula nesting exceeds the representable De Bruijn index")]
fn binding_fails_closed_when_de_bruijn_depth_overflows() {
    let x = FreeVariable::new(1);
    let mut body = Node::ForAll(Box::new(Node::Equal(Variable::Free(x), Variable::Free(x))));

    bind_free(&mut body, u32::MAX, &|candidate| {
        (candidate == x).then_some(0)
    });
}

#[test]
fn alpha_renamed_binders_have_the_same_representation() {
    let x = FreeVariable::new(1);
    let y = FreeVariable::new(2);

    let with_x = Formula::for_all(x, Formula::equal(x, x));
    let with_y = Formula::for_all(y, Formula::equal(y, y));

    assert_eq!(with_x, with_y);
}

#[test]
fn nested_binders_retain_their_correct_indices() {
    let x = FreeVariable::new(1);
    let y = FreeVariable::new(2);
    let formula = Formula::for_all(x, Formula::for_all(y, Formula::member(x, y)));

    assert_eq!(
        formula,
        Formula(Node::ForAll(Box::new(Node::ForAll(Box::new(
            Node::Member(Variable::Bound(1), Variable::Bound(0)),
        )))))
    );
    assert!(formula.is_closed());
}

#[test]
fn multiple_binders_match_repeated_binding_with_nesting_and_duplicates() {
    let x = FreeVariable::new(1);
    let y = FreeVariable::new(2);
    let z = FreeVariable::new(3);
    let variables = [x, y, x];
    let body = Formula::for_all(
        z,
        Formula::implies(Formula::member(x, z), Formula::equal(y, x)),
    );
    let expected = variables
        .iter()
        .rev()
        .fold(body.clone(), |formula, variable| {
            Formula::for_all(*variable, formula)
        });

    assert_eq!(Formula::for_all_many(&variables, body), expected);
}

#[test]
fn closure_check_finds_a_free_variable_under_a_binder() {
    let x = FreeVariable::new(1);
    let y = FreeVariable::new(2);
    let formula = Formula::for_all(
        x,
        Formula::implies(Formula::equal(x, x), Formula::member(y, x)),
    );

    assert!(!formula.is_closed());
}

#[test]
fn free_substitution_changes_only_matching_free_variables_across_the_tree() {
    let bound = FreeVariable::new(1);
    let from = FreeVariable::new(2);
    let to = FreeVariable::new(3);
    let untouched = FreeVariable::new(4);
    let formula = Formula::for_all(
        bound,
        Formula::implies(
            Formula::negate(Formula::member(bound, from)),
            Formula::implies(Formula::equal(from, untouched), Formula::member(to, from)),
        ),
    );

    let substituted = formula.substitute_free(from, to);
    let expected = Formula::for_all(
        bound,
        Formula::implies(
            Formula::negate(Formula::member(bound, to)),
            Formula::implies(Formula::equal(to, untouched), Formula::member(to, to)),
        ),
    );

    assert_eq!(substituted, expected);
}

#[test]
fn free_substitution_is_a_no_op_for_absent_or_identical_variables() {
    let x = FreeVariable::new(1);
    let y = FreeVariable::new(2);
    let absent = FreeVariable::new(3);
    let formula = Formula::member(x, y);

    assert_eq!(formula.clone().substitute_free(absent, x), formula);
    assert_eq!(formula.clone().substitute_free(x, x), formula);
}

#[test]
fn free_variable_mapping_is_simultaneous_and_preserves_bound_variables() {
    let x = FreeVariable::new(1);
    let y = FreeVariable::new(2);
    let z = FreeVariable::new(3);
    let mapped = Formula::implies(Formula::member(x, y), Formula::equal(y, z)).map_free_variables(
        |variable| match variable {
            variable if variable == x => y,
            variable if variable == y => z,
            _ => x,
        },
    );

    assert_eq!(
        mapped,
        Formula::implies(Formula::member(y, z), Formula::equal(z, x))
    );

    let under_binder = Formula::for_all(x, Formula::member(x, y)).map_free_variables(|_| x);
    assert_eq!(under_binder.primitive_structure(), "all(mem(b0,f1))");
}

#[test]
fn derived_connectives_use_only_primitive_nodes() {
    let x = FreeVariable::new(1);
    let y = FreeVariable::new(2);
    let left = Formula::equal(x, x);
    let right = Formula::member(x, y);

    assert_eq!(
        Formula::disjunction(left.clone(), right.clone()),
        Formula::implies(Formula::negate(left), right)
    );
}

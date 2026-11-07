//! Frozen 7c4f94d5 generation strategy for explicit matched experiments only.
use super::*;
pub(in crate::frontier) fn questions(
    cursor: u64,
    seeds: &VecDeque<Formula>,
    goals: &VecDeque<CompiledQuestion>,
    maximum: usize,
    bytes: usize,
    eligible: &mut dyn FnMut(&CompiledQuestion) -> bool,
) -> Vec<CompiledQuestion> {
    let mut groups = Vec::new();
    for goal in goals
        .iter()
        .rev()
        .cycle()
        .skip(cursor as usize % goals.len().max(1))
        .take(goals.len().min(4))
    {
        groups.push(VecDeque::from(helpers(goal, cursor)));
    }
    let a = FreeVariable::new(0);
    let b = FreeVariable::new(1);
    let mut relations = vec![Formula::member(a, b), Formula::equal(a, b)];
    let checked = seeds
        .iter()
        .filter(|f| f.free_variables().len() == 2 && f.view().node_count_and_depth().0 <= 24)
        .collect::<Vec<_>>();
    relations.extend(
        checked
            .iter()
            .cycle()
            .skip(cursor as usize % checked.len().max(1))
            .take(checked.len().min(4))
            .map(|f| (*f).clone()),
    );
    let original = relations.len();
    let primitive = relations.clone();
    relations.extend(primitive.iter().filter_map(inclusion));
    let mut checked_questions = VecDeque::new();
    let mut free_questions = VecDeque::new();
    for offset in 0..20 {
        let index = (cursor as usize + offset) % relations.len();
        let seed = &relations[index];
        if let Some(formula) = property(seed, cursor / relations.len() as u64 + offset as u64)
            && let Ok(question) = CompiledQuestion::from_formula(formula)
        {
            if index % original < 2 {
                free_questions.push_back(question);
            } else {
                checked_questions.push_back(question);
            }
        }
    }
    groups.extend([checked_questions, free_questions]);
    let length = groups.len();
    groups.rotate_left(cursor as usize % length);
    let mut all = Vec::new();
    while groups.iter().any(|g| !g.is_empty()) {
        for group in &mut groups {
            if let Some(q) = group.pop_front() {
                all.push(q);
            }
        }
    }
    bounded_eligible(all, maximum, bytes, eligible)
}

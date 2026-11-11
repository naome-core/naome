use super::*;

#[test]
fn a_prefix_normalizes_only_against_its_legal_siblings() {
    let device = Device::flex();
    let logits = Tensor::from_data([[0., 3f32.ln(), 2f32.ln(), 0.]], &device);
    let siblings = Tensor::from_data(
        [[
            [false, false, true, true],
            [false, false, true, true],
            [true, true, false, false],
            [true, true, false, false],
        ]],
        &device,
    );
    let paths = Tensor::from_data(
        [[[1., 0., 1., 0.], [1., 0., 0., 1.], [0., 1., 0., 0.]]],
        &device,
    );
    let probabilities = prefix_probabilities(logits, siblings, paths)
        .exp()
        .into_data()
        .try_to_vec::<f32>()
        .unwrap();
    for (actual, expected) in probabilities.into_iter().zip([1. / 6., 1. / 12., 3. / 4.]) {
        assert!((actual - expected).abs() < 1e-6);
    }
}

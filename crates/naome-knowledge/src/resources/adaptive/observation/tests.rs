use super::*;

#[test]
fn process_tree_counts_owned_descendants_and_excludes_unrelated_processes() {
    let (rss, cpu, own) = process_tree(
        "10 1 100 0:01.50\n11 10 200 0:02.00\n12 11 300 1-00:00:01\n13 1 9999 9:00\n",
        10,
    )
    .unwrap();
    assert_eq!(own, 100 * 1024);
    assert_eq!(rss, 600 * 1024);
    assert_eq!(cpu, 86_404_500);
}

#[test]
fn cpu_times_cover_both_supported_ps_formats_and_long_running_processes() {
    assert_eq!(cpu_time("173:22.62").unwrap(), 10_402_620);
    assert_eq!(cpu_time("02:53:22").unwrap(), 10_402_000);
    assert!(cpu_time("00:60:00").is_err());
    assert!(cpu_time("NaN").is_err());
    assert!(cpu_time("00:NaN").is_err());
    assert!(cpu_time("-1:00").is_err());
}

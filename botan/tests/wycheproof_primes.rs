#[test]
fn test_wycheproof_primality() -> Result<(), botan::Error> {
    use wycheproof::{primality::*, TestResult};

    let mut rng = botan::RandomNumberGenerator::new_system()?;

    for test_name in TestName::all() {
        let test_set = TestSet::load(test_name).expect("OK");

        for test_group in &test_set.test_groups {
            for test in &test_group.tests {
                if test.flags.contains(&TestFlag::NegativeOfPrime) {
                    continue;
                }
                let mpi = botan::MPI::new_from_bytes(&test.value)?;
                let is_prime = mpi.is_prime(&mut rng, 128)?;

                assert_eq!(is_prime, test.result == TestResult::Valid);
            }
        }
    }

    Ok(())
}

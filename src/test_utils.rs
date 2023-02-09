use std::fmt;

pub struct TestCase<Payload, Criteria> {
    pub name:     &'static str,
    pub payload:  Payload,
    pub criteria: Criteria,
}

impl<Payload, Criteria> fmt::Display for TestCase<Payload, Criteria> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "test `{}`", self.name)
    }
}

/// asserts `failed` == `total` then prints the corresponding status message
pub fn status_message(failed: usize, total: usize) {
    if failed == 0 {
        println!("all passed!")
    } else {
        panic!("failed {}/{} tests", failed, total)
    }
}

/// checks if `res == expected` then prints the corresponding status message
pub fn check_output_match<T>(expected: &T, res: &T) -> bool
where
    T: fmt::Debug + PartialEq,
{
    if expected != res {
        println!("test returned wrong value: `{expected:?}` != `{res:?}`");
        false
    } else {
        println!("ok!");
        true
    }
}

impl<Payload, Criteria> TestCase<Payload, Criteria> {
    /// runs the tests using the given function and criteria matcher
    fn runner<FnOut, F, Matcher, In1, In2>(tests: Vec<Self>, func: F, matcher: Matcher)
    where
        Criteria: Into<In1>,
        FnOut: Into<In2>,
        F: Fn(Payload) -> FnOut,
        Matcher: Fn(&In1, &In2) -> bool,
    {
        let len = tests.len();
        let failed = tests
            .into_iter()
            .map(|test| {
                print!("{test}: ");
                let res = func(test.payload);
                matcher(&test.criteria.into(), &res.into())
            })
            .filter(|t| !t)
            .count();

        status_message(failed, len);
    }

    /// Runs all tests with the given function and asserts the output exactly
    /// matches `self.criteria`. Requires `self.criteria` to be the same
    /// type as the output of the given test function. Will panic if any
    /// tests fail to match the expected criteria. If you're matching a
    /// `Result` and want a more detailed error message, then try
    /// [`TestCase::run_result_match`]
    pub fn run_output_match<F>(tests: Vec<Self>, func: F)
    where
        Criteria: PartialEq + fmt::Debug,
        F: Fn(Payload) -> Criteria,
    {
        Self::runner(tests, func, check_output_match::<Criteria>);
    }
}

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MyServiceError {
    pub message: String,
}

impl fmt::Display for MyServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

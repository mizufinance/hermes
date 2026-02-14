use core::fmt::{Display, Error as FmtError, Formatter};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Specs {
    pub bankd: Option<String>,
}

impl Display for Specs {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        let bankd = self
            .bankd
            .as_deref()
            .unwrap_or("UNKNOWN");

        write!(f, "Bankd {}", bankd)
    }
}

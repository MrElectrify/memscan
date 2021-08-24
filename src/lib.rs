use std::str::FromStr;

use subslice_index::subslice_index;

/// A memory pattern. Wildcards are represented in raw buffers
/// as null bytes
pub struct Pattern {
    buf: Vec<u8>
}

impl From<&[u8]> for Pattern {
    fn from(buf: &[u8]) -> Pattern {
        Pattern { buf: Vec::from(buf) }
    }
}

/// This is not recommended, but is provided as a compatibility layer for
/// those who have signatures in IDA format, for example
impl FromStr for Pattern {
    type Err = usize;

    /// The index of the bad pattern character is returned
    fn from_str(buf_str: &str) -> Result<Pattern, Self::Err> {
        let mut buf = Vec::new();
        for byte_str in buf_str.split_ascii_whitespace() {
            if byte_str == "?" {
                buf.push(0x00);
            } else {
                match u8::from_str_radix(byte_str, 16) {
                    Ok(byte) => { buf.push(byte); },
                    Err(_) => { return Err(subslice_index(buf_str.as_bytes(), byte_str.as_bytes())) }
                };    
            }
        }
        Ok(Pattern{ buf })
    }
}

/// Finds a pattern in a buffer
///
/// # Arguments
///
/// `buf`: The buffer to search for the pattern in
/// `pattern`: The pattern to find
pub fn find_pattern(buf: &[u8], pattern: Pattern) -> Option<Vec<&[u8]>> {
    None
}
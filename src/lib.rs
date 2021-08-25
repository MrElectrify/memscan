use rayon::prelude::*;
use std::str::FromStr;
use subslice_index::subslice_index;

/// A memory pattern. Wildcards are represented in raw buffers
/// as null bytes. Must not be empty
pub struct Pattern {
    buf: Vec<u8>,
}

impl Pattern {
    /// Tests if a pattern matches a slice of bytes
    ///
    /// # Arguments
    ///
    /// `buf`: The slice of bytes
    pub fn matches(&self, buf: &[u8]) -> bool {
        self.buf
            .par_iter()
            .zip(buf.par_iter())
            .all(|(&pattern_byte, &buffer_byte)| {
                pattern_byte == 0x00 || pattern_byte == buffer_byte
            })
    }
}

impl From<&[u8]> for Pattern {
    fn from(buf: &[u8]) -> Pattern {
        Pattern {
            buf: Vec::from(buf),
        }
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
                    Ok(byte) => {
                        buf.push(byte);
                    }
                    Err(_) => return Err(subslice_index(buf_str.as_bytes(), byte_str.as_bytes())),
                };
            }
        }
        Ok(Pattern { buf })
    }
}

/// Finds a pattern in a buffer
///
/// # Arguments
///
/// `buf`: The buffer to search for the pattern in
/// `pattern`: The pattern to find. Must not be empty
pub fn find_pattern(buf: &[u8], pattern: Pattern) -> Vec<&[u8]> {
    buf.par_windows(pattern.buf.len())
        .filter(|&window| pattern.matches(window))
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[should_panic]
    fn empty_pattern() {
        let buf = &[1, 2, 3];
        let pattern = Pattern::from(&[][..]);
        find_pattern(buf, pattern);
    }

    #[test]
    fn not_empty() {
        let buf = &[1, 2, 3];
        let pattern = Pattern::from(&[1, 2][..]);
        assert!(!find_pattern(buf, pattern).is_empty());
    }

    #[test]
    fn empty() {
        let buf = &[1, 2, 3];
        let pattern = Pattern::from(&[1, 3][..]);
        assert!(find_pattern(buf, pattern).is_empty());
    }

    #[test]
    fn simple_wildcard_not_empty() {
        let buf = &[1, 2, 3];
        let pattern = Pattern::from(&[1, 0x00, 3][..]);
        assert!(!find_pattern(buf, pattern).is_empty());
    }

    #[test]
    fn simple_wildcard_empty() {
        let buf = &[1, 2, 3];
        let pattern = Pattern::from(&[1, 0x00, 4][..]);
        assert!(find_pattern(buf, pattern).is_empty());
    }

    #[test]
    fn wildcard_start_not_empty() {
        let buf = &[1, 2, 3];
        let pattern = Pattern::from(&[0x00, 3][..]);
        assert!(!find_pattern(buf, pattern).is_empty());
    }

    #[test]
    fn wildcard_start_empty() {
        let buf = &[1, 2, 3];
        let pattern = Pattern::from(&[0x00, 1][..]);
        assert!(find_pattern(buf, pattern).is_empty());
    }

    #[test]
    fn wildcard_end_not_empty() {
        let buf = &[1, 2, 3];
        let pattern = Pattern::from(&[1, 2, 0x00][..]);
        assert!(!find_pattern(buf, pattern).is_empty());
    }

    #[test]
    fn wildcard_end_empty() {
        let buf = &[1, 2, 3];
        let pattern = Pattern::from(&[2, 3, 0x00][..]);
        assert!(find_pattern(buf, pattern).is_empty());
    }

    #[test]
    fn multi_match() {
        let buf = &[1, 2, 3, 4, 3, 2, 1, 2, 3];
        let pattern = Pattern::from(&[1, 2, 0x00][..]);
        assert_eq!(find_pattern(buf, pattern).len(), 2);
    }

    #[test]
    fn function_signature() {
        let buf = include_bytes!("..\\test\\crt.exe");
        let pattern = Pattern::from(
            &[
                0xe8, 0x00, 0x00, 0x00, 0x00, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 0xd8,
            ][..],
        );
        let result = find_pattern(buf, pattern);
        assert!(!result.is_empty());
        assert_eq!(
            result[0],
            &[0xe8, 0x1c, 0x04, 0x00, 0x00, 0xe8, 0xcb, 0x05, 0x00, 0x00, 0x48, 0x8b, 0xd8][..]
        );
        assert_eq!(subslice_index(buf, result[0]), 0x5bb);
    }
}

# memscan
A simple pattern-based memory scanning tool. Provides support for both slices as patterns with 0x00 as wildcards, and IDA-format (? as wildcard)

## Usage
- Create a `Pattern` with `Pattern::from_str("aa bb ? dd ee").expect("Index of parse falure")` or `Pattern::from(&[0xaa, 0xbb, 0x00, 0xdd, 0xee])`
- Check if that pattern matches a slice with `find_pattern(slice, &pattern)`, returning each matching slice

## Example
```rs
fn multi_match() {
    let buf = &[1, 2, 3, 4, 3, 2, 1, 2, 3];
    let pattern = Pattern::from(&[1, 2, 0x00][..]);
    assert_eq!(find_pattern(buf, pattern).len(), 2);
}
```
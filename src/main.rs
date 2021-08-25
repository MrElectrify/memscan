use memscan::{Pattern, find_pattern};
use std::{env, str::FromStr};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <buf:hex> <pattern:pattern>", &args[0]);
        return Ok(());
    }
    let buf = hex::decode(&args[1])?;
    let pattern = match Pattern::from_str(&args[2]) {
        Ok(pattern) => pattern,
        Err(idx) => { eprintln!("Pattern parse error at index {}", idx); return Ok(()) }
    };
    let result = find_pattern(&buf, pattern);
    println!("Result: {:?}", result);
    Ok(())
}
use std::{path::Path, sync::atomic::AtomicBool};
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 3);
    let policy: uli_ups::health::HttpHealth =
        serde_json::from_slice(&std::fs::read(Path::new(&args[1])).unwrap()).unwrap();
    match policy.probe(&args[2], &AtomicBool::new(false)) {
        Ok(observation) => println!(
            "{}",
            serde_json::json!({"status":observation.status,"release_header_matched":observation.release_header_matched})
        ),
        Err(error) => {
            eprintln!("{}", error.0);
            std::process::exit(1);
        }
    }
}

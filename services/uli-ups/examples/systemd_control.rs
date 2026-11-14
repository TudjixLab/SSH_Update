use std::{path::Path, sync::atomic::AtomicBool};
use uli_ups::systemd::SystemdControl;
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        4,
        "root-owned policy, expected instance, action"
    );
    let control = SystemdControl::load(Path::new(&args[1]), &args[2]).unwrap();
    let cancel = AtomicBool::new(false);
    match args[3].as_str() {
        "status" => println!(
            "{}",
            serde_json::to_string(&control.status(&cancel).unwrap()).unwrap()
        ),
        "start" => control.request_start(&cancel).unwrap(),
        "stop" => control.request_stop(&cancel).unwrap(),
        "restart" => control.request_restart(&cancel).unwrap(),
        _ => panic!("unsupported example action"),
    }
}

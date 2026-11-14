#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = run() {
        eprintln!("{{\"code\":\"{}\"}}", error.0);
        std::process::exit(1);
    }
}
#[cfg(target_os = "linux")]
fn run() -> uli_ups::Result<()> {
    use std::{io::Read, path::Path};
    use uli_ups::{Error, agent::Agent, config::Config};
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--version"] {
        println!("uli-ups {}", uli_ups::VERSION);
        return Ok(());
    }
    if args == ["--help"] {
        println!(
            "uli-ups serve --config ABS_PATH\nuli-ups request --config ABS_PATH < request.json\nuli-ups stage-upload --config ABS_PATH --upload-id ID --request-id ID\nuli-ups build-worker --policy ROOT_OWNED_JSON\nuli-ups --version"
        );
        return Ok(());
    }
    if args.len() == 3 && args[0] == "build-worker" && args[1] == "--policy" {
        println!("{}", uli_ups::build_worker::run(Path::new(&args[2]))?);
        return Ok(());
    }
    if args.len() < 3 || args[1] != "--config" {
        return Err(Error("AGENT_ARGUMENTS_INVALID"));
    }
    let config = Config::load(Path::new(&args[2]))?;
    match args[0].as_str() {
        "serve" if args.len() == 3 => uli_ups::control::serve(Agent::open(config)?),
        "request" if args.len() == 3 => {
            let mut bytes = Vec::new();
            std::io::stdin().take(65537).read_to_end(&mut bytes)?;
            let response = uli_ups::control::request(&config, &bytes)?;
            println!("{}", response);
            if response["body"]["type"] == "error" {
                return Err(Error("AGENT_REQUEST_REJECTED"));
            }
            Ok(())
        }
        "stage-upload"
            if args.len() == 7 && args[3] == "--upload-id" && args[5] == "--request-id" =>
        {
            let mut agent = Agent::open(config)?;
            println!("{}", agent.stage_upload(&args[4], &args[6])?);
            Ok(())
        }
        _ => Err(Error("AGENT_ARGUMENTS_INVALID")),
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("AGENT_LINUX_REQUIRED");
    std::process::exit(1);
}

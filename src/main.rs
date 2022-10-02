use std::env;
#[macro_use]
extern crate log;

mod udp_server;

fn main() {
    env::set_var("RUST LOG", "debug");
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        error!("Invalid arguments.");
        std::process::exit(1);
    }

    let address = &args[1];

    udp_server::serve(address).unwrap_or_else(|e| eprintln!("{}", e));
}

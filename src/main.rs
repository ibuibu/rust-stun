use std::env;

mod udp_server;
mod util;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Invalid arguments.");
        std::process::exit(1);
    }

    let address_port = &args[1];

    udp_server::serve(address_port).unwrap_or_else(|e| eprintln!("{}", e));
}

use clap::Parser;

use envo::cli::Cli;
use envo::{commands, output};

fn main() {
    let cli = Cli::parse();
    output::init_color(cli.no_color);

    match commands::dispatch(cli) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("{} {:#}", output::red("error:"), e);
            std::process::exit(2);
        }
    }
}

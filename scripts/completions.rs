//! Shared implementation for the host-side Cargo completion examples.

use clap::CommandFactory;
use clap_complete::Shell;
use std::io::{self, ErrorKind, Write};
use std::path::PathBuf;

pub fn generate<C: CommandFactory>() -> io::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let directory = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "usage: completions OUTPUT_DIRECTORY"))?;
    if args.next().is_some() {
        return Err(io::Error::new(ErrorKind::InvalidInput, "expected one output directory"));
    }
    let mut command = C::command();
    let name = command.get_name().to_owned();
    for (shell, subdir, filename) in [
        (Shell::Bash, "bash", format!("{name}.bash")),
        (Shell::Zsh, "zsh", format!("_{name}")),
        (Shell::Fish, "fish", format!("{name}.fish")),
    ] {
        let mut script = Vec::new();
        clap_complete::generate(shell, &mut command, &name, &mut script);
        let output = directory.join(subdir);
        std::fs::create_dir_all(&output)?;
        let mut file = std::fs::File::create(output.join(filename))?;
        file.write_all(&script)?;
    }
    Ok(())
}

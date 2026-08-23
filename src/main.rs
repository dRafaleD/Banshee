use std::process::ExitCode;

fn main() -> ExitCode {
    match banshee::run() {
        Ok(banshee::RunOutcome::Success) => ExitCode::SUCCESS,
        Ok(banshee::RunOutcome::Findings) => ExitCode::from(1),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(2)
        }
    }
}

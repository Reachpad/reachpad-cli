//! reachpad — the CLI (§5.8). Thin shell over the `reach` lib; all command
//! logic is in-process drivable (the I6 integration test depends on that).

#[tokio::main]
async fn main() {
    match reach::run(std::env::args().collect()).await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("reachpad: {e:#}");
            std::process::exit(1);
        }
    }
}

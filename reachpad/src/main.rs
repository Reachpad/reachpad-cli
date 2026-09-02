//! reachpad — the CLI (§5.8). Thin shell over the `reach` lib; all command
//! logic is in-process drivable (the I6 integration test depends on that).

#[tokio::main]
async fn main() {
    match reach::run(std::env::args().collect()).await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            // `reach::out`, not `eprintln!`: this file is the bin crate, so
            // the lib's shadowing macros do not reach it, and `2>&1 | head`
            // must not turn the last word into a panic (issue #56).
            reach::out::err_line(format_args!("reachpad: {e:#}"));
            std::process::exit(1);
        }
    }
}

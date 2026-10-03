//! Finite loopback server. Only public configuration enters this process.
use naome_submission::{Admission, MAX_BYTES};
use serde_json::json;
use std::{
    env,
    fs::File,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

fn read_exact(stream: &mut TcpStream, mut bytes: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "frame deadline"))?;
        stream.set_read_timeout(Some(remaining))?;
        let count = stream.read(bytes)?;
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        bytes = &mut bytes[count..];
    }
    Ok(())
}
fn handle(stream: &mut TcpStream, admission: &mut Admission, deadline: Instant) -> io::Result<()> {
    // Accepted sockets can inherit nonblocking mode on macOS. Per-request
    // deadlines require blocking reads with the remaining absolute allowance.
    stream.set_nonblocking(false)?;
    let mut prefix = [0; 4];
    read_exact(stream, &mut prefix, deadline)?;
    let size = u32::from_be_bytes(prefix) as usize;
    let response = if size == 0 || size > MAX_BYTES {
        json!({"error":"frame_limit"})
    } else {
        let mut bytes = vec![0; size];
        read_exact(stream, &mut bytes, deadline)?;
        match admission.submit(&bytes) {
            Ok(receipt) => json!({"receipt":receipt}),
            Err(error) => json!({"error":error}),
        }
    };
    let bytes = serde_json::to_vec(&response)?;
    let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
    frame.extend(bytes);
    let mut remaining = frame.as_slice();
    let write_deadline = Instant::now() + Duration::from_secs(1);
    while !remaining.is_empty() {
        let allowance = write_deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "response deadline"))?;
        stream.set_write_timeout(Some(allowance))?;
        let count = stream.write(remaining)?;
        if count == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        remaining = &remaining[count..];
    }
    Ok(())
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 {
        return Err("usage: naome-submission PUBLIC_CONFIGURATION LOOPBACK_ADDRESS".into());
    }
    let address: SocketAddr = args[2].parse()?;
    if !address.ip().is_loopback() {
        return Err("loopback address required".into());
    }
    let mut bytes = Vec::new();
    File::open(&args[1])?
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    let mut admission = Admission::from_configuration(&bytes)?;
    let listener = TcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    println!(
        "{}",
        json!({"address":listener.local_addr()?.to_string(),"context":admission.context(),"max_connections":128,"lifetime_seconds":300})
    );
    io::stdout().flush()?;
    let end = Instant::now() + Duration::from_secs(300);
    let mut connections = 0;
    while Instant::now() < end && connections < 128 {
        match listener.accept() {
            Ok((mut stream, _)) => {
                connections += 1;
                let deadline = (Instant::now() + Duration::from_secs(2)).min(end);
                // Transport failures close this connection; they never stop the
                // session or mutate admission state before a complete request.
                if let Err(error) = handle(&mut stream, &mut admission, deadline) {
                    eprintln!("connection rejected: {error}");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10))
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

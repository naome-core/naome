use std::{
    io,
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};

#[derive(Default)]
struct State {
    blocked: bool,
    stopped: bool,
    sockets: Vec<TcpStream>,
    accepted: usize,
    refused: usize,
    allow_backend_restart: bool,
}

/// An opaque TCP path. Only the validator processes terminate Noise/Yamux.
pub struct Gate {
    listener: Option<TcpListener>,
    address: SocketAddr,
    state: Arc<Mutex<State>>,
    worker: Option<JoinHandle<()>>,
}

impl Gate {
    pub fn allow_backend_restart(&self) {
        self.state.lock().unwrap().allow_backend_restart = true;
    }
    pub fn bind() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        Self {
            address: listener.local_addr().unwrap(),
            listener: Some(listener),
            state: Arc::default(),
            worker: None,
        }
    }

    pub fn address(&self) -> String {
        format!("/ip4/127.0.0.1/tcp/{}", self.address.port())
    }

    pub fn start(&mut self, backend: SocketAddr) {
        let listener = self.listener.take().unwrap();
        let state = self.state.clone();
        self.worker = Some(thread::spawn(move || {
            let mut copies = Vec::new();
            loop {
                if state.lock().unwrap().stopped {
                    break;
                }
                let incoming = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("gate accept: {error}"),
                };
                // Accepted sockets inherit O_NONBLOCK on macOS. The copy
                // workers use blocking I/O and are interrupted by shutdown.
                incoming.set_nonblocking(false).unwrap();
                let mut shared = state.lock().unwrap();
                if shared.blocked {
                    shared.refused += 1;
                    assert!(shared.refused <= 64, "bounded refused gate connections");
                    let _ = incoming.shutdown(Shutdown::Both);
                    continue;
                }
                drop(shared);
                let outgoing = match TcpStream::connect_timeout(&backend, Duration::from_secs(1)) {
                    Ok(stream) => stream,
                    Err(error) => {
                        let mut shared = state.lock().unwrap();
                        assert!(shared.allow_backend_restart, "gate backend failed: {error}");
                        shared.refused += 1;
                        assert!(shared.refused <= 64, "bounded restart connection attempts");
                        let _ = incoming.shutdown(Shutdown::Both);
                        continue;
                    }
                };
                // Cut and registration share the lock. A connection established
                // during a cut cannot start forwarding after cut returns.
                let mut shared = state.lock().unwrap();
                if shared.blocked {
                    shared.refused += 1;
                    let _ = incoming.shutdown(Shutdown::Both);
                    let _ = outgoing.shutdown(Shutdown::Both);
                    continue;
                }
                shared.accepted += 1;
                assert!(shared.accepted <= 4, "bounded forwarded gate connections");
                shared.sockets.push(incoming.try_clone().unwrap());
                shared.sockets.push(outgoing.try_clone().unwrap());
                drop(shared);
                for (mut read, mut write) in [
                    (incoming.try_clone().unwrap(), outgoing.try_clone().unwrap()),
                    (outgoing, incoming),
                ] {
                    copies.push(thread::spawn(move || {
                        // EOF and reset are both expected when a path is cut.
                        let _ = io::copy(&mut read, &mut write);
                        let _ = read.shutdown(Shutdown::Both);
                        let _ = write.shutdown(Shutdown::Both);
                    }));
                }
            }
            for copy in copies {
                copy.join().unwrap();
            }
        }));
    }

    pub fn cut(&self) {
        let mut shared = self.state.lock().unwrap_or_else(|error| error.into_inner());
        shared.blocked = true;
        for stream in &shared.sockets {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    pub fn counts(&self) -> (usize, usize) {
        let shared = self.state.lock().unwrap();
        (shared.accepted, shared.refused)
    }

    fn stop(&mut self) -> Option<JoinHandle<()>> {
        self.cut();
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .stopped = true;
        self.worker.take()
    }

    pub fn finish(&mut self) {
        if let Some(worker) = self.stop() {
            worker.join().unwrap();
        }
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        if let Some(worker) = self.stop() {
            let _ = worker.join();
        }
    }
}

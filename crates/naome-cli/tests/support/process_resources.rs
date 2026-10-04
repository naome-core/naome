use std::{
    collections::BTreeSet,
    net::TcpListener,
    sync::{Arc, Condvar, LazyLock, Mutex},
    time::{Duration, Instant},
};

const LAB_LIMIT: usize = 2;
const PORTS_PER_LAB: u16 = 12;

struct Pool {
    active: Mutex<(usize, usize)>,
    available: Condvar,
}
impl Pool {
    const fn new() -> Self {
        Self {
            active: Mutex::new((0, 0)),
            available: Condvar::new(),
        }
    }
    fn acquire(&self) -> Slot<'_> {
        let started = Instant::now();
        let mut active = self.active.lock().unwrap_or_else(|p| p.into_inner());
        while active.0 == LAB_LIMIT {
            active = self
                .available
                .wait(active)
                .unwrap_or_else(|p| p.into_inner());
        }
        active.0 += 1;
        active.1 = active.1.max(active.0);
        Slot {
            pool: self,
            waited: started.elapsed(),
        }
    }
}

pub(super) struct Slot<'a> {
    pool: &'a Pool,
    waited: Duration,
}
impl Drop for Slot<'_> {
    fn drop(&mut self) {
        let mut active = self.pool.active.lock().unwrap_or_else(|p| p.into_inner());
        active.0 -= 1;
        self.pool.available.notify_one();
        eprintln!(
            "process_slot_metrics={{\"case\":{:?},\"wait_seconds\":{},\"peak_labs\":{}}}",
            std::thread::current().name().unwrap_or("unknown"),
            self.waited.as_secs_f64(),
            active.1
        );
    }
}

pub(super) fn admit() -> Slot<'static> {
    static LABS: Pool = Pool::new();
    LABS.acquire()
}

#[derive(Default)]
struct Ports(Mutex<BTreeSet<u16>>);
impl Ports {
    fn acquire(self: &Arc<Self>, seed: u32) -> PortLease {
        let mut reserved = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let base = (0..1000)
            .find_map(|offset| {
                let base = 20000 + (seed.wrapping_add(offset) % 40000) as u16;
                if reserved.iter().any(|other| overlaps(base, *other)) {
                    return None;
                }
                let probes = (0..PORTS_PER_LAB)
                    .map(|i| TcpListener::bind(("127.0.0.1", base + i)))
                    .collect::<std::io::Result<Vec<_>>>()
                    .ok()?;
                // Logical ownership outlives these probes: validators must bind
                // the ports themselves. External processes are not reserved out.
                reserved.insert(base);
                drop(probes);
                Some(base)
            })
            .expect("no available nonoverlapping twelve-port Lab span");
        PortLease {
            ports: Arc::clone(self),
            base,
        }
    }
}
fn overlaps(a: u16, b: u16) -> bool {
    a < b + PORTS_PER_LAB && b < a + PORTS_PER_LAB
}

pub(super) struct PortLease {
    ports: Arc<Ports>,
    pub(super) base: u16,
}
impl PortLease {
    pub(super) fn acquire(seed: u32) -> Self {
        static PORTS: LazyLock<Arc<Ports>> = LazyLock::new(|| Arc::new(Ports::default()));
        PORTS.acquire(seed)
    }
}
impl Drop for PortLease {
    fn drop(&mut self) {
        self.ports
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.base);
    }
}

#[test]
fn third_lab_waits_for_a_slot_and_unwind_releases_it() {
    let pool = Arc::new(Pool::new());
    let first = pool.acquire();
    let second = pool.acquire();
    let worker_pool = Arc::clone(&pool);
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _third = worker_pool.acquire();
        tx.send(()).unwrap();
    });
    assert!(rx.recv_timeout(Duration::from_millis(30)).is_err());
    assert_eq!(*pool.active.lock().unwrap(), (2, 2));
    let result = std::panic::catch_unwind(|| {
        let _held = first;
        panic!("injected slot-owner unwind");
    });
    assert!(result.is_err());
    rx.recv_timeout(Duration::from_secs(5)).unwrap();
    worker.join().unwrap();
    drop(second);
    assert_eq!(*pool.active.lock().unwrap(), (0, 2));
}

#[test]
fn port_leases_prevent_partial_overlap_and_release_after_unwind() {
    assert!(overlaps(20000, 20011));
    assert!(!overlaps(20000, 20012));
    let ports = Arc::new(Ports::default());
    let first = ports.acquire(12345);
    let first_base = first.base;
    let second = ports.acquire(12345);
    assert!(!overlaps(first.base, second.base));
    let result = std::panic::catch_unwind(|| {
        let _held = first;
        panic!("injected port-owner unwind");
    });
    assert!(result.is_err());
    assert!(!ports.0.lock().unwrap().contains(&first_base));
    assert!(ports.0.lock().unwrap().contains(&second.base));
    drop(second);
    assert!(ports.0.lock().unwrap().is_empty());
}

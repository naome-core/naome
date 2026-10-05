use std::{
    collections::BTreeSet,
    net::TcpListener,
    sync::{Arc, Condvar, LazyLock, Mutex},
    time::{Duration, Instant},
};

const LAB_LIMIT: usize = 2;
const PORTS_PER_LAB: u16 = 12;

struct Pool {
    active: Mutex<Admission>,
    available: Condvar,
}
#[derive(Default)]
struct Admission {
    active: usize,
    peak: usize,
    exclusive: bool,
    waiting_exclusive: usize,
}
impl Pool {
    const fn new() -> Self {
        Self {
            active: Mutex::new(Admission {
                active: 0,
                peak: 0,
                exclusive: false,
                waiting_exclusive: 0,
            }),
            available: Condvar::new(),
        }
    }
    fn acquire(&self) -> Slot<'_> {
        self.acquire_mode(false)
    }
    fn acquire_mode(&self, exclusive: bool) -> Slot<'_> {
        let started = Instant::now();
        let mut active = self.active.lock().unwrap_or_else(|p| p.into_inner());
        if exclusive {
            active.waiting_exclusive += 1;
            self.available.notify_all();
        }
        while active.exclusive
            || if exclusive {
                active.active != 0
            } else {
                active.active == LAB_LIMIT || active.waiting_exclusive != 0
            }
        {
            active = self
                .available
                .wait(active)
                .unwrap_or_else(|p| p.into_inner());
        }
        if exclusive {
            active.waiting_exclusive -= 1;
            active.exclusive = true;
        }
        active.active += 1;
        active.peak = active.peak.max(active.active);
        Slot {
            pool: self,
            waited: started.elapsed(),
            exclusive,
        }
    }
}

pub(super) struct Slot<'a> {
    pool: &'a Pool,
    waited: Duration,
    exclusive: bool,
}
impl Drop for Slot<'_> {
    fn drop(&mut self) {
        let mut active = self.pool.active.lock().unwrap_or_else(|p| p.into_inner());
        active.active -= 1;
        if self.exclusive {
            active.exclusive = false;
        }
        self.pool.available.notify_all();
        eprintln!(
            "process_slot_metrics={{\"case\":{:?},\"wait_seconds\":{},\"peak_labs\":{},\"exclusive\":{}}}",
            std::thread::current().name().unwrap_or("unknown"),
            self.waited.as_secs_f64(),
            active.peak,
            self.exclusive
        );
    }
}

static LABS: Pool = Pool::new();

pub(super) fn admit() -> Slot<'static> {
    LABS.acquire()
}

pub(super) fn admit_exclusive() -> Slot<'static> {
    LABS.acquire_mode(true)
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
    assert_eq!(pool.active.lock().unwrap().active, 2);
    let result = std::panic::catch_unwind(|| {
        let _held = first;
        panic!("injected slot-owner unwind");
    });
    assert!(result.is_err());
    rx.recv_timeout(Duration::from_secs(5)).unwrap();
    worker.join().unwrap();
    drop(second);
    let state = pool.active.lock().unwrap();
    assert_eq!((state.active, state.peak), (0, 2));
}

#[test]
fn exclusive_lab_drains_the_same_pool_blocks_new_labs_and_unwinds() {
    let pool = Arc::new(Pool::new());
    let first = pool.acquire();
    let second = pool.acquire();
    let exclusive_pool = Arc::clone(&pool);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let exclusive = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(|| {
            let _slot = exclusive_pool.acquire_mode(true);
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            panic!("injected exclusive Lab-owner unwind");
        });
        assert!(result.is_err());
    });
    let started = Instant::now();
    while pool.active.lock().unwrap().waiting_exclusive == 0 {
        assert!(started.elapsed() < Duration::from_secs(5));
        std::thread::yield_now();
    }
    // One freed ordinary slot must not admit a new Lab ahead of the drainer.
    drop(first);
    let ordinary_pool = Arc::clone(&pool);
    let (ordinary_tx, ordinary_rx) = std::sync::mpsc::channel();
    let ordinary = std::thread::spawn(move || {
        let _slot = ordinary_pool.acquire();
        ordinary_tx.send(()).unwrap();
    });
    assert!(ordinary_rx.recv_timeout(Duration::from_millis(30)).is_err());
    assert!(entered_rx.try_recv().is_err());
    drop(second);
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(ordinary_rx.recv_timeout(Duration::from_millis(30)).is_err());
    {
        let state = pool.active.lock().unwrap();
        assert_eq!(state.active, 1);
        assert!(state.exclusive);
    }
    release_tx.send(()).unwrap();
    exclusive.join().unwrap();
    ordinary_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    ordinary.join().unwrap();
    let state = pool.active.lock().unwrap();
    assert_eq!(
        (state.active, state.peak, state.waiting_exclusive),
        (0, 2, 0)
    );
    assert!(!state.exclusive);
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

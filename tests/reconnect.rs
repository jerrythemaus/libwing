//! Offline coverage for reconnect + session recovery (U5, R2/R42/R43/R44): bounded-backoff
//! reconnect over a real (localhost) TCP socket, session-gap reporting, and give-up behavior.
//!
//! Uses real `TcpListener`/`TcpStream` pairs on loopback rather than `from_transports` --
//! reconnect re-establishes a genuine TCP connection to `peer_ip:peer_port`, which a scripted
//! transport can't fabricate (see `WingConsole::reconnect`'s docs on `from_transports`
//! consoles). `WingConsole::connect_addr` is the public entry point that lets a test target an
//! arbitrary port instead of the hardcoded 2222 `connect()` uses.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use libwing::{Error, Meter, ReconnectPolicy, WingConsole};

fn local_listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

/// Happy path (R2): a dropped connection reconnects within backoff, and the gap is flagged
/// rather than hidden (R42).
#[test]
fn reconnect_after_drop_succeeds_and_flags_gap() {
    let (listener, addr) = local_listener();
    let mut console = WingConsole::connect_addr(addr).unwrap();
    let (server, _) = listener.accept().unwrap();

    // Drop the server half: the client's next read sees the FIN as a graceful close (`Ok(0)`),
    // which `decode_next` treats as a connection error rather than "keep waiting".
    drop(server);
    assert!(console.read().is_err());

    // The listener's backlog completes the new TCP handshake even without a second thread
    // calling `accept()` here -- the kernel accept queue handles it up to the backlog size.
    let outcome = console.reconnect(&ReconnectPolicy::default()).unwrap();
    assert_eq!(outcome.attempts, 1);
    assert!(outcome.gap.dropped_events);
    assert!(outcome.gap.state_may_have_changed);
    assert!(
        !outcome.gap.meters_invalidated,
        "no meter subscription existed"
    );

    // The reconnected session is actually usable.
    console.request_node_data(1).unwrap();

    drop(listener);
}

/// R42: a live meter subscription is flagged invalidated across a reconnect -- the UDP socket
/// survives, but the server-side subscription doesn't, so consumers must re-subscribe.
#[test]
fn reconnect_flags_meter_subscription_invalidated() {
    let (listener, addr) = local_listener();
    let mut console = WingConsole::connect_addr(addr).unwrap();
    let (server, _) = listener.accept().unwrap();

    console.request_meter(&[Meter::Channel(1)]).unwrap();

    drop(server);
    assert!(console.read().is_err());

    let outcome = console.reconnect(&ReconnectPolicy::default()).unwrap();
    assert!(outcome.gap.meters_invalidated);
    assert!(outcome.gap.dropped_events);
    assert!(outcome.gap.state_may_have_changed);

    drop(listener);
}

/// Backoff + give-up: repeated failures sleep with bounded exponential backoff rather than
/// busy-looping, and `reconnect` returns a clear error once `max_attempts` is exhausted.
#[test]
fn reconnect_gives_up_after_max_attempts_with_backoff() {
    let (listener, addr) = local_listener();
    let mut console = WingConsole::connect_addr(addr).unwrap();
    let (server, _) = listener.accept().unwrap();
    drop(server);
    assert!(console.read().is_err());

    // Close the listener so the peer port is truly dead (connection refused, not just slow).
    drop(listener);

    let policy = ReconnectPolicy {
        max_attempts: 3,
        initial_backoff: Duration::from_millis(20),
        max_backoff: Duration::from_millis(200),
    };
    let start = Instant::now();
    let err = console.reconnect(&policy).unwrap_err();
    let elapsed = start.elapsed();

    assert!(matches!(err, Error::Io(_) | Error::ConnectionError));
    // Two sleeps between three attempts: 20ms then 40ms (doubled, well under the 200ms cap).
    assert!(
        elapsed >= Duration::from_millis(55),
        "expected backoff sleeps to have elapsed, got {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "reconnect should not hang on a refused connection, got {elapsed:?}"
    );
}

/// Design decision: a console built over injected transports (tests/replay, no real peer) can't
/// fabricate a TCP reconnection, so `reconnect` fails fast and explicitly instead of silently
/// no-op'ing or panicking.
#[test]
fn reconnect_on_transport_injected_console_is_invalid_input() {
    let (listener, addr) = local_listener();
    let client = TcpStream::connect(addr).unwrap();
    let (_server, _) = listener.accept().unwrap();
    let mut console = WingConsole::from_transports(
        client.try_clone().unwrap(),
        client,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    );

    let err = console.reconnect(&ReconnectPolicy::default()).unwrap_err();
    assert!(matches!(err, Error::InvalidInput));
}

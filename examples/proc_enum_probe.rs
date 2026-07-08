//! One-off: fetch the live `/ch/1/proc` enum ordering and diff it against the embedded propmap.
//! Confirms whether the processing-order enum has drifted (which would make index-based writes
//! land on the wrong permutation). Run: `cargo run --example proc_enum_probe -- 192.168.178.201`
use libwing::WingConsole;
use std::time::Duration;

fn main() {
    let host = std::env::args().nth(1);
    let mut console = WingConsole::connect(host.as_deref()).expect("connect");
    let (def, _) = console
        .get_node_definition_by_name("/ch/1/proc", Duration::from_secs(3))
        .expect("fetch /ch/1/proc def");

    let live: Vec<String> = def
        .string_enum
        .unwrap_or_default()
        .into_iter()
        .map(|i| i.item)
        .collect();
    let embedded: Vec<String> = WingConsole::name_to_def("/ch/1/proc")
        .and_then(|d| d.string_enum.clone())
        .unwrap_or_default()
        .into_iter()
        .map(|i| i.item)
        .collect();

    println!("idx  live    embedded  match");
    let n = live.len().max(embedded.len());
    let mut drift = false;
    for i in 0..n {
        let l = live.get(i).map(String::as_str).unwrap_or("-");
        let e = embedded.get(i).map(String::as_str).unwrap_or("-");
        let ok = l == e;
        if !ok {
            drift = true;
        }
        println!("{i:3}  {l:<7} {e:<8} {}", if ok { "" } else { "<-- DIFF" });
    }
    println!(
        "\n{}",
        if drift {
            "DRIFT: live /proc enum order != embedded propmap -> index-based writes are WRONG"
        } else {
            "no drift: live and embedded /proc enum orders match"
        }
    );
}

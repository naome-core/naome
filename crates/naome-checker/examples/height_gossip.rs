//! Offline experiment only. No production finality, network, storage or rewards.
//! Run with: cargo run -p naome-checker --example height_gossip --release -- 4 10 7 partition reversible 3 random
mod height_gossip_model;

fn main() {
    height_gossip_model::run();
}

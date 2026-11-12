fn main() {
    cfg_if::cfg_if! {
        if #[cfg(any(unix, windows))] {
            println!("CFG_IF=ok");
        } else {
            println!("CFG_IF=other");
        }
    }
}

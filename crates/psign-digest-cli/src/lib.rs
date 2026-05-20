#[allow(dead_code)]
mod imp {
    include!("main.rs");
}

pub use imp::run_from;

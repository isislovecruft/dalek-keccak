#![feature(nll)]

mod reference;

pub use reference::State;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

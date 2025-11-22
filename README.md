<!-- cargo-rdme start -->

# Happy Eyeballs v3 Implementation

WORK IN PROGRESS

This crate provides a pure state machine implementation of Happy Eyeballs v3
as specified in [draft-ietf-happy-happyeyeballs-v3-02](https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html).

Happy Eyeballs v3 is an algorithm for improving the performance of dual-stack
applications by racing IPv4 and IPv6 connections while optimizing for modern
network conditions including HTTPS service discovery and QUIC.

## Usage

```rust
use happy_eyeballs::*;
use std::time::Instant;

let start_time = Instant::now();
let mut he = HappyEyeballs::new("example.com".to_string(), 443, start_time);

// Process until we get outputs or timers
loop {
    match he.process(None) {
        Output::None => break,
        output => {
            // Handle the output (DNS query, connection attempt, etc.)
            println!("Output: {:?}", output);
        }
    }
}
```

<!-- cargo-rdme end -->

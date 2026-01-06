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

let mut he = HappyEyeballs::new("example.com".into(), 443);

let mut now = Instant::now();
loop {
    match he.process(None, now) {
        None => break, // nothing more to do right now
        Some(Output::SendDnsQuery { hostname, record_type }) => {
            let response = match record_type {
                DnsRecordType::Https => {
                    let mut alpn = HashSet::new();
                    alpn.insert(Protocol::H3);
                    alpn.insert(Protocol::H2);
                    DnsResponse {
                        target_name: hostname.clone(),
                        inner: DnsResponseInner::Https(Ok(vec![ServiceInfo {
                            priority: 1,
                            target_name: TargetName::from("example.com"),
                            alpn_protocols: alpn,
                            ech_config: None,
                            ipv4_hints: vec![Ipv4Addr::new(192, 0, 2, 1)],
                            ipv6_hints: vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)],
                        }])),
                    }
                }
                DnsRecordType::Aaaa => DnsResponse {
                    target_name: hostname.clone(),
                    inner: DnsResponseInner::Aaaa(Ok(vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)])),
                },
                DnsRecordType::A => DnsResponse {
                    target_name: hostname.clone(),
                    inner: DnsResponseInner::A(Ok(vec![Ipv4Addr::new(192, 0, 2, 1)])),
                },
            };
            let _ = he.process(Some(Input::DnsResponse(response)), now);
        }
        Some(Output::AttemptConnection { endpoint }) => {
            let _ = he.process(
                Some(Input::ConnectionResult { address: endpoint.address, result: Ok(()) }),
                now,
            );
            break;
        }
        Some(Output::CancelConnection(_addr)) => {}
        Some(Output::Timer { duration }) => {
            now += duration;
        }
    }
}
```

<!-- cargo-rdme end -->

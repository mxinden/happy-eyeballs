use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Instant,
};

use happy_eyeballs::{
    DnsAResponse, DnsAaaaResponse, DnsHttpsResponse, DnsRecordType, DnsResponse, HappyEyeballs,
    Input, NetworkConfig, Output,
};

const HOSTNAME: &str = "example.com";
const PORT: u16 = 443;
const V6_ADDR: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const V4_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

trait HappyEyeballsExt {
    fn expect(&mut self, input_output: Vec<(Option<Input>, Option<Output>)>, now: Instant);
}

impl HappyEyeballsExt for HappyEyeballs {
    fn expect(&mut self, input_output: Vec<(Option<Input>, Option<Output>)>, now: Instant) {
        for (input, expected_output) in input_output {
            let output = self.process(input, now);
            assert_eq!(output, expected_output);
        }
    }
}

fn in_dns_https_positive() -> Input {
    Input::DnsResponse(DnsResponse::Https(DnsHttpsResponse::Positive {
        addresses: vec![],
        service_info: None,
    }))
}

fn in_dns_https_negative() -> Input {
    Input::DnsResponse(DnsResponse::Https(DnsHttpsResponse::Negative))
}

fn in_dns_aaaa_positive() -> Input {
    Input::DnsResponse(DnsResponse::Aaaa(DnsAaaaResponse::Positive {
        addresses: vec![V6_ADDR],
    }))
}

fn in_dns_a_positive() -> Input {
    Input::DnsResponse(DnsResponse::A(DnsAResponse::Positive {
        addresses: vec![V4_ADDR],
    }))
}

fn in_dns_aaaa_negative() -> Input {
    Input::DnsResponse(DnsResponse::Aaaa(DnsAaaaResponse::Negative))
}

fn in_dns_a_negative() -> Input {
    Input::DnsResponse(DnsResponse::A(DnsAResponse::Negative))
}

fn out_send_dns_https() -> Output {
    Output::SendDnsQuery {
        hostname: HOSTNAME.to_string(),
        record_type: DnsRecordType::Https,
    }
}

fn out_send_dns_aaaa() -> Output {
    Output::SendDnsQuery {
        hostname: HOSTNAME.to_string(),
        record_type: DnsRecordType::Aaaa,
    }
}

fn out_send_dns_a() -> Output {
    Output::SendDnsQuery {
        hostname: HOSTNAME.to_string(),
        record_type: DnsRecordType::A,
    }
}

fn out_attempt_v6() -> Output {
    Output::AttemptConnection {
        address: SocketAddr::new(V6_ADDR.into(), PORT),
        protocol_info: None,
    }
}

fn out_attempt_v4() -> Output {
    Output::AttemptConnection {
        address: SocketAddr::new(V4_ADDR.into(), PORT),
        protocol_info: None,
    }
}

fn setup() -> (Instant, HappyEyeballs) {
    setup_with_config(NetworkConfig::default())
}

fn setup_with_config(config: NetworkConfig) -> (Instant, HappyEyeballs) {
    let now = Instant::now();
    let he = HappyEyeballs::with_network_config(HOSTNAME.to_string(), PORT, config);
    (now, he)
}

#[test]
fn initial_state() {
    let (now, mut he) = setup();

    he.expect(vec![(None, Some(out_send_dns_https()))], now);
}

/// > 4. Hostname Resolution
///
/// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4>
#[cfg(test)]
mod section_4_hostname_resolution {
    use happy_eyeballs::RESOLUTION_DELAY;

    use super::*;

    /// > All of the DNS queries SHOULD be made as soon after one another as
    /// > possible. The order in which the queries are sent SHOULD be as follows
    /// > (omitting any query that doesn't apply based on the logic described
    /// > above):
    /// >
    /// > 1. SVCB or HTTPS query
    /// > 2. AAAA query
    /// > 3. A query
    ///
    /// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.1>
    #[test]
    fn sendig_dns_queries() {
        let (now, mut he) = setup();

        he.expect(
            vec![
                (None, Some(out_send_dns_https())),
                (None, Some(out_send_dns_aaaa())),
                (None, Some(out_send_dns_a())),
            ],
            now,
        );
    }

    /// > Implementations SHOULD NOT wait for all answers to return before
    /// > starting the next steps of connection establishment.
    ///
    /// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
    #[test]
    fn dont_wait_for_all_dns_answers() {
        let (now, mut he) = setup();

        he.expect(
            vec![
                (None, Some(out_send_dns_https())),
                (None, Some(out_send_dns_aaaa())),
                (None, Some(out_send_dns_a())),
                (Some(in_dns_https_positive()), None),
                (Some(in_dns_aaaa_positive()), Some(out_attempt_v6())),
            ],
            now,
        );
    }

    /// > The client moves onto sorting addresses and establishing
    /// > connections once one of the following condition sets is met:
    /// >
    /// > Either:
    /// >
    /// > - Some positive (non-empty) address answers have been received AND
    /// > - A postive (non-empty) or negative (empty) answer has been
    ///     received for the preferred address family that was queried AND
    /// > - SVCB/HTTPS service information has been received (or has received a negative response)
    ///
    /// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
    #[test]
    fn move_on_non_timeout() {
        #[derive(Debug)]
        struct Case {
            address_family: NetworkConfig,
            positive: Input,
            preferred: Option<Input>,
            expected: Option<Output>,
        }

        let test_cases = vec![
            // V6 preferred, V6 positive, HTTPS positive, expect V6 connection attempt
            Case {
                address_family: NetworkConfig::DualStack { prefer_ipv6: true },
                positive: in_dns_aaaa_positive(),
                preferred: None,
                expected: Some(out_attempt_v6()),
            },
            // V6 preferred, V4 positive, V6 positive, HTTPS positive, expect V6 connection attempt
            Case {
                address_family: NetworkConfig::DualStack { prefer_ipv6: true },
                positive: in_dns_a_positive(),
                preferred: Some(in_dns_aaaa_positive()),
                expected: Some(out_attempt_v6()),
            },
            // V6 preferred, V6 negative, V4 positive, HTTPS positive, expect V4 connection attempt
            Case {
                address_family: NetworkConfig::DualStack { prefer_ipv6: true },
                positive: in_dns_a_positive(),
                preferred: Some(in_dns_aaaa_negative()),
                expected: Some(out_attempt_v4()),
            },
            // V4 preferred, V4 positive, HTTPS positive, expect V4 connection attempt
            Case {
                address_family: NetworkConfig::DualStack { prefer_ipv6: false },
                positive: in_dns_a_positive(),
                preferred: None,
                expected: Some(out_attempt_v4()),
            },
            // V4 preferred, V6 positive, V4 positive, HTTPS positive, expect V4 connection attempt
            Case {
                address_family: NetworkConfig::DualStack { prefer_ipv6: false },
                positive: in_dns_aaaa_positive(),
                preferred: Some(in_dns_a_positive()),
                expected: Some(out_attempt_v4()),
            },
            // V4 preferred, V4 negative, V6 positive, HTTPS positive, expect V6 connection attempt
            Case {
                address_family: NetworkConfig::DualStack { prefer_ipv6: false },
                positive: in_dns_aaaa_positive(),
                preferred: Some(in_dns_a_negative()),
                expected: Some(out_attempt_v6()),
            },
        ];

        for test_case in test_cases {
            for https in [in_dns_https_positive(), in_dns_https_negative()] {
                let (now, mut he) = setup_with_config(test_case.address_family.clone());

                he.expect(
                    vec![
                        (None, Some(out_send_dns_https())),
                        (None, Some(out_send_dns_aaaa())),
                        (None, Some(out_send_dns_a())),
                        (Some(test_case.positive.clone()), None),
                        (test_case.preferred.clone(), None),
                        (Some(https), test_case.expected.clone()),
                    ],
                    now,
                );
            }
        }
    }

    /// > Or:
    /// >
    /// > - Some positive (non-empty) address answers have been received AND
    /// > - A resolution time delay has passed after which other answers have not been received
    ///
    /// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
    // TODO: Other combinations
    #[test]
    fn move_on_timeout() {
        let (mut now, mut he) = setup();

        he.expect(
            vec![
                (None, Some(out_send_dns_https())),
                (None, Some(out_send_dns_aaaa())),
                (None, Some(out_send_dns_a())),
                (Some(in_dns_a_positive()), None),
            ],
            now,
        );

        now += RESOLUTION_DELAY;

        he.expect(vec![(None, Some(out_attempt_v4()))], now);
    }

    /// > ServiceMode records can contain address hints via ipv6hint and
    /// > ipv4hint parameters. When these are received, they SHOULD be
    /// > considered as positive non-empty answers for the purpose of the
    /// > algorithm when A and AAAA records corresponding to the TargetName
    /// > are not available yet.
    ///
    /// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2.1>
    #[test]
    #[ignore]
    fn https_hints() {
        todo!();
    }

    /// > Note that clients are still required to issue A and AAAA queries
    /// > for those TargetNames if they haven't yet received those records.
    ///
    /// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2.1>
    #[test]
    #[ignore]
    fn https_hints_still_query_a_aaaa() {
        todo!();
    }
}

use ipp::ip_processor::{IpInput, IpProcessor};
use std::net::{IpAddr, Ipv4Addr};

#[tokio::test]
async fn test_single_ip() {
    let input = IpInput::Single(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));
    let ips = IpProcessor::generate_ips(input, false, 10);
    assert_eq!(ips.len(), 1);
    assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));
}

#[tokio::test]
async fn test_cidr() {
    let input = IpInput::Cidr("192.168.0.0/30".parse().unwrap());
    let ips = IpProcessor::generate_ips(input, false, 10);
    assert_eq!(ips.len(), 2);
    assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));
    assert_eq!(ips[1], IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2)));
}

#[tokio::test]
async fn test_cidr_include_all() {
    let input = IpInput::Cidr("192.168.0.0/30".parse().unwrap());
    let ips = IpProcessor::generate_ips(input, true, 10);
    assert_eq!(ips.len(), 4);
}

#[tokio::test]
async fn test_ip_range() {
    let start = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
    let end = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 3));
    let input = IpInput::Range((start, end));
    let ips = IpProcessor::generate_ips(input, false, 10);
    assert_eq!(ips.len(), 3);
}

#[tokio::test]
async fn test_max_ips() {
    let input = IpInput::Cidr("192.168.0.0/24".parse().unwrap());
    let ips = IpProcessor::generate_ips(input, false, 5);
    assert_eq!(ips.len(), 5);
}

#[tokio::test]
async fn test_invalid_input() {
    let result = IpProcessor::parse_input("invalid");
    assert!(result.is_err());
}

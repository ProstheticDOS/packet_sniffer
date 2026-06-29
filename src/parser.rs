use std::net::{IpAddr, Ipv4Addr};

#[derive(PartialEq)]
pub enum TransportLayerProtocol {
    UDP,
    TCP,
    ICMP,
}

pub struct ParsedDataPacket {
    transport_headers: Option<TransportHeader>,
    protocol: TransportLayerProtocol,
    destination_ip_address: IpAddr,
    source_ip_address: IpAddr,
    source_port: Option<u16>,      // in case of ICMP
    destination_port: Option<u16>, // in case of ICMP
    payload: Vec<u8>,
}

pub fn parse_packet(
    number_of_bytes: usize,
    payload: &[u8],
) -> Result<ParsedDataPacket, std::io::Error> {
    let net_headers = parsed.net;
    let transport_header = parsed.transport;

    let mut protocol = TransportLayerProtocol::ICMP; // or add Unknown variant

    let (source_port, destination_port) = match transport_header {
        Some(etherparse::TransportHeader::Udp(ref udp)) => {
            protocol = TransportLayerProtocol::UDP;
            (Some(udp.source_port), Some(udp.destination_port))
        }
        Some(etherparse::TransportHeader::Tcp(ref tcp)) => {
            protocol = TransportLayerProtocol::TCP;
            (Some(tcp.source_port), Some(tcp.destination_port))
        }
        _ => (None, None),
    };

    let (source_ip, destination_ip) = match net_headers {
        Some(etherparse::NetHeaders::Ipv4(ref header, _)) => (
            IpAddr::V4(Ipv4Addr::from(header.source)),
            IpAddr::V4(Ipv4Addr::from(header.destination)),
        ),

        Some(etherparse::NetHeaders::Ipv6(ref header, _)) => (
            IpAddr::V6(Ipv6Addr::from(header.source)),
            IpAddr::V6(Ipv6Addr::from(header.destination)),
        ),

        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "No IP header found",
            ));
        }
    };

    Ok(ParsedDataPacket {
        transport_headers: transport_header,
        protocol,
        destination_ip_address: destination_ip,
        source_ip_address: source_ip,
        source_port,
        destination_port,
        payload: parsed.payload.slice().to_vec(),
    })
}

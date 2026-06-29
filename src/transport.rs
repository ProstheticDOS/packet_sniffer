use std::io::Result;

use anyhow::Error;

pub fn send_packet_to_internet(env: &mut JNIEnv, data_packet: &ParsedDataPacket) -> Result<(), Error> {
    // sending packets back to the internet

    let udp_socket = std::net::UdpSocket::bind(&data_packet.destination_port)?;

    udp_socket.connect(&data_packet.destination_ip_address)?;

    udp_socket.send(&data_packet.payload)?;
}

pub fn recieve_packets_from_the_internet(data_packet: &ParsedDataPacket) 

    let mut rx_buffer = [0u8; 2048];
    let recieved_data = std::net::UdpSocket::recv_from(&udp_socket, &mut rx_buffer)?;

    // name is reveesed when recieving data, we are also not parsing recieved data since ip
    // addresses specifcally will be the same in both sent packet and recieved packet
    let destination_address: &IpAddr = &data_packet.source_ip_address.parse()?.octets_into();
    let source_address: &IpAddr = &data_packet.destination_ip_address.parse()?.octets_into();

    let recieved_packet_headers =
        etherparse::PacketHeaders::from_ip_slice(&rx_buffer[..recieved_data.0])?;
    let net_headers = recieved_packet_headers.net?;

    let mut time_to_live: u8 = 0;

    match net_headers {
        etherparse::NetHeaders::Ipv4(ref header, _) => {
            time_to_live = header.time_to_live;
        }
        etherparse::NetHeaders::Ipv6(ref header, _) => {
            time_to_live = header.hop_limit;
        }
        _ => (),
    }

    //TODO: use octets to build a packet using etherparse

    let y = etherparse::PacketBuilder::ipv4(source_address, destination_address, time_to_live);

    let message = format!("{:?}", y);
    print_on_screen(message, env);

    Result::Ok(y);
}

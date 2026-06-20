use core::net;
use etherparse::err::tcp;
use etherparse::{
    IpHeader, IpHeaders, Ipv4Dscp, Ipv6ExtensionSlice, NetHeaders, PacketHeaders, PayloadSlice,
    TcpHeader, TransportHeader, UdpHeader, ether_type,
};
use jni::JNIEnv;
use jni::objects::{JClass, JValue};
use jni::sys::jint;
use std::fs::File;
use std::io::{BufRead, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::FromRawFd;
use std::os::fd::IntoRawFd;
use std::thread::park_timeout;
use std::{env, vec};

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_packetsniffer_NativeBridge_runPacketLoop(
    mut env: JNIEnv,
    _class: JClass,
    file_descriptor: jint, // the file descriptor
) {
    // Reading from vpn_file_descriptor advances the pointer, hence we need to make it mutable
    let mut vpn_file_descriptor = unsafe { File::from_raw_fd(file_descriptor) };

    #[cfg(debug_assertions)]
    {
        let message = "Hello from rust side!!".to_string();
        print_on_screen(&message, &mut env);
    }
    {
        scan_packets(&mut env, &vpn_file_descriptor);
    }

    let file_descriptor_string = file_descriptor.to_string();
    print_on_screen(&file_descriptor_string, &mut env);

    let mut buffer = vec![0u8; 1500];

    // into_raw_fd() extracts the FD and tells Rust "Don't close this when you drop."
    let _ = vpn_file_descriptor.into_raw_fd();
}

enum TransportLayerProtocol {
    UDP,
    TCP,
    Unknown, //initial unassigned value
}

struct ParsedDataPacket {
    net_headers: Option<NetHeaders>,
    transport_headers: Option<TransportHeader>,
    protocol: TransportLayerProtocol,
    destination_ip_address: String,
    source_ip_address: String,
    source_port: String,
    destination_port: String,
}

fn print_on_screen(message: &String, env: &mut JNIEnv) {
    let message = env.new_string(message).unwrap();
    env.call_static_method(
        "com/example/packetsniffer/NativeBridge",
        "printOnScreen",
        "(Ljava/lang/String;)V",
        &[JValue::Object(&message.into())],
    );
}

fn formatted_bytes_as_string(
    number_of_bytes: usize,
    payload: &Vec<u8>,
    env: &mut JNIEnv,
) -> String {
    let payload_data = &payload[..number_of_bytes];
    let message = format!("Read {} bytes: {:?}", &number_of_bytes, &payload_data).to_string();
    message
}

fn scan_packets(env: &mut JNIEnv, mut vpn_file_descriptor: &File) {
    let mut buffer = vec![0u8; 1500];
    loop {
        match vpn_file_descriptor.read(&mut buffer) {
            Ok(bytes) => {
                if bytes == 0 {
                    break;
                }
            }

            Err(error) => {
                let error_message: String = format!("Unable to read packet: {}", error);

                print_on_screen(&error_message, env);
            }
        }
    }
}

fn parse_packets(number_of_bytes: usize, payload: &Vec<u8>, env: &mut JNIEnv) {
    if let Ok(parsed) = PacketHeaders::from_ip_slice(&payload[..number_of_bytes]) {
        let net_headers = parsed.net;
        let mut source_ip = String::new();
        let mut destination_ip = String::new();
        let mut protocol = TransportLayerProtocol::Unknown;
        let transport_header = parsed.transport;
        let mut source_port = String::new();
        let mut destination_port = String::new();

        // gets us port and protocol information
        match transport_header {
            Some(etherparse::TransportHeader::Udp(ref udp)) => {
                protocol = TransportLayerProtocol::UDP;
                source_port = udp.source_port.to_string();
                destination_port = udp.destination_port.to_string();
            }
            Some(etherparse::TransportHeader::Tcp(ref tcp)) => {
                protocol = TransportLayerProtocol::TCP;
                source_port = tcp.source_port.to_string();
                destination_port = tcp.destination_port.to_string();
            }
            _ => (), // Don't want to deal with ICMP, not that important anyway (says an amateur)
        }

        match net_headers {
            Some(etherparse::NetHeaders::Ipv4(ref header, _)) => {
                source_ip = Ipv4Addr::from(header.source).to_string();
                destination_ip = Ipv4Addr::from(header.destination).to_string();
            }

            Some(etherparse::NetHeaders::Ipv6(ref header, _)) => {
                source_ip = Ipv6Addr::from(header.source).to_string();
                destination_ip = Ipv6Addr::from(header.destination).to_string();
            }

            _ => (),
        }
        let parsed_data_packet = ParsedDataPacket {
            source_port: source_port,
            destination_port: destination_port,
            protocol: protocol,
            transport_headers: transport_header,
            net_headers: net_headers,
            source_ip_address: source_ip,
            destination_ip_address: destination_ip,
        };
    }
}

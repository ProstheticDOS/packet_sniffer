use anyhow::Ok;
use domain::base::Message;
use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use jni::JNIEnv;
use jni::objects::{JClass, JValue};
use jni::sys::jint;
use memmap2::Mmap;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::FromRawFd;
use std::thread::sleep;
use std::time::Duration;
use std::vec;

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_packetsniffer_NativeBridge_runPacketLoop(
    mut env: JNIEnv,
    _class: JClass,
    file_descriptor: jint, // the file descriptor
) {
    // Reading from vpn_file_descriptor advances the pointer, hence we need to make it mutable
    let mut vpn_file_descriptor = unsafe { File::from_raw_fd(file_descriptor) };

    let file_descriptor_string = file_descriptor.to_string();
    print_on_screen(&file_descriptor_string, &mut env);

    let mut buffer = vec![0u8; 1500];
    let mut number_of_bytes: usize = 0;

    loop {
        match vpn_file_descriptor.read(&mut buffer) {
            Result::Ok(bytes) => {
                number_of_bytes = bytes;
            }
            Result::Err(error) => continue,
        }

        let data_packet = parse_packet(number_of_bytes, &buffer);

        // print packet headers
        let packet_payload = &buffer[..number_of_bytes];

        match data_packet {
            Result::Ok(packet_info) => {
                if packet_info.protocol == TransportLayerProtocol::UDP
                    && packet_info.destination_port == "53".to_string()
                {
                    let udp_payload = packet_info.payload;
                    let domain_name = get_domain_name(&udp_payload);

                    if domain_name.kind == DomainNameOrError::Name {
                        print_on_screen(&domain_name.name, &mut env);
                        let comparasion_against_list =
                            check_domain_name_against_list(domain_name.name);
                        match comparasion_against_list {
                            Result::Ok(answer) => {
                                if answer == YesOrNo::Yes {
                                    let message = "This domain is in the list!".to_string();
                                    print_on_screen(&message, &mut env);
                                }
                            }

                            Result::Err(error) => {
                                if error.kind() != std::io::ErrorKind::NotFound {
                                    ();
                                } else {
                                    let message = error.to_string();
                                    print_on_screen(&message, &mut env);
                                };
                            }
                        }
                    }
                };
            }

            Result::Err(error) => (),
        }

        let domain_name = get_domain_name(packet_payload);
        #[cfg(debug_assertions)]
        print_debug_info(&buffer, &mut env, number_of_bytes);
    }
}

#[derive(PartialEq)]
enum TransportLayerProtocol {
    UDP,
    TCP,
    Unknown, //initial unassigned value
}

#[derive(PartialEq)]
enum DomainNameOrError {
    Name,
    Error,
}

struct ParsedDataPacket {
    net_headers: Option<NetHeaders>,
    transport_headers: Option<TransportHeader>,
    protocol: TransportLayerProtocol,
    destination_ip_address: String,
    source_ip_address: String,
    source_port: String,
    destination_port: String,
    payload: Vec<u8>,
}

struct DomainName {
    name: String,
    kind: DomainNameOrError,
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

fn formatted_bytes_as_string(number_of_bytes: usize, payload: &Vec<u8>) -> String {
    let payload_data = &payload[..number_of_bytes];
    let message = format!("Read {} bytes: {:?}", &number_of_bytes, &payload_data).to_string();
    message
}

fn print_raw_packets(env: &mut JNIEnv, mut vpn_file_descriptor: &File) {
    let mut buffer = vec![0u8; 1500];
    loop {
        match vpn_file_descriptor.read(&mut buffer) {
            Result::Ok(bytes) => {
                if bytes == 0 {
                    break;
                }
                let message = bytes.to_string();
                print_on_screen(&message, env);
            }

            Err(error) => {
                let error_message: String = format!("Unable to read packet: {}", error);

                print_on_screen(&error_message, env);
                continue;
            }
        }
    }
}

fn parse_packet(number_of_bytes: usize, payload: &[u8]) -> Result<ParsedDataPacket, anyhow::Error> {
    let parsed = PacketHeaders::from_ip_slice(&payload[..number_of_bytes])?;

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
        payload: parsed.payload.slice().to_vec(), // payload slice
    };

    let packet = etherparse::IpSlice::from_slice(payload);

    Ok(parsed_data_packet)
}

fn print_debug_info(buffer: &Vec<u8>, env: &mut JNIEnv, number_of_bytes: usize) {
    let data_packet = parse_packet(number_of_bytes, buffer);
    // print packet headers
    match data_packet {
        Result::Ok(packet) => {
            if packet.protocol == TransportLayerProtocol::UDP
                || packet.protocol == TransportLayerProtocol::TCP
            {
                let message = format!(
                    "Transport haders: {:?} waiting 2 seconds",
                    packet.transport_headers
                )
                .to_string();

                print_on_screen(&message, env);
                sleep(Duration::from_secs(2));

                // Printing Ip slices
                match etherparse::IpSlice::from_slice(&buffer[..number_of_bytes]) {
                    Result::Ok(value) => {
                        let message = format!("Ip slice is: {:?}, waiting 2 seconds", value);
                        print_on_screen(&message, env);
                        sleep(Duration::from_secs(2));
                    }
                    Result::Err(error) => {
                        let message = format!("Error {:?}", error);
                        print_on_screen(&message, env);
                        sleep(Duration::from_secs(2));
                    }
                };
            }

            if packet.protocol == TransportLayerProtocol::UDP {
                // print UDP slice
                match etherparse::UdpSlice::from_slice(&buffer[..number_of_bytes]) {
                    Result::Ok(value) => {
                        let message = format!("Udp slice: {:?}", value);
                        print_on_screen(&message, env);
                        sleep(Duration::from_secs(2));
                    }
                    Result::Err(error) => {
                        let message = format!(
                            "Unable to parse udp slice (even though it's supposed to be udp?) {:?}",
                            error
                        );
                        print_on_screen(&message, env);
                        sleep(Duration::from_secs(2));
                    }
                }
            }

            if packet.protocol == TransportLayerProtocol::TCP {
                match etherparse::TcpSlice::from_slice(&buffer[..number_of_bytes]) {
                    Result::Ok(value) => {
                        let message = format!("TCP slice {:?}", value);
                        print_on_screen(&message, env);
                        sleep(Duration::from_secs(2));
                    }
                    Result::Err(error) => {
                        let message = format!(
                            "Unable to parse tcp slice (even though it's supposed to be tcp?), {:?}",
                            error
                        );

                        print_on_screen(&message, env);
                        sleep(Duration::from_secs(2));
                    }
                }
            }
        }
        Err(error) => {
            let message = format!("Error: {:?}, trying again in 2 seconds", error);
            sleep(Duration::from_secs(2));
        }
    }
}

fn get_domain_name(packet_payload: &[u8]) -> DomainName {
    let message = Message::from_slice(packet_payload);

    let mut return_struct = DomainName {
        name: "Placeholder".to_string(),
        kind: DomainNameOrError::Error,
    };

    match message {
        Result::Ok(message) => {
            for question in message.question() {
                match question {
                    Result::Ok(question_value) => {
                        return_struct.name = question_value.qname().to_string();
                        return_struct.kind = DomainNameOrError::Name;
                    }

                    Result::Err(error) => {
                        return_struct.name = error.to_string();
                    }
                }
            }
        }
        Result::Err(error) => {
            return_struct.name = error.to_string();
        }
    }

    return_struct
}

#[derive(PartialEq)]
enum YesOrNo {
    Yes,
    No,
}

// This function uses Finite state trancuders to make the lookup efficient
fn check_domain_name_against_list(domain_name: String) -> Result<YesOrNo, std::io::Error> {
    let file = File::open("data/user/0/com.example.packetsniffer/files/list.txt")?;
    let mmap = unsafe { Mmap::map(&file)? };
    let file_contents = &mmap[..];
    let mut result = YesOrNo::No;

    let lines_iter = file_contents.split(|&byte| byte == b'\n');
    for (line_number, line_bytes) in lines_iter.enumerate() {
        if line_bytes == domain_name.as_bytes() {
            result = YesOrNo::Yes;
        }
    }
    Result::Ok(result)
}

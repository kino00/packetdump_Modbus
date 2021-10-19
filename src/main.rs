extern crate pnet;

use pnet::datalink::{self, NetworkInterface};

use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;

use std::env;
use std::io::{self, Write};
use std::net::IpAddr;
use std::process;

fn handle_modbus(packet: &[u8], r_flag: bool) {
    let fc = packet[0];
    print!("Function Code: {} ", fc);
    match fc {
        1 => {
            if r_flag {
                let byc = packet[1];
                println!("Read Coil Status Respons");
                println!("Byte Count: {}", byc);
                for i in 0 .. byc {
                    println!("data{}~{}: {:08b}"
                        ,i * 8, i * 8 + 7, packet[(2 + i) as usize]);
                }
            } else {
                let rn = ((packet[1] as u16) << 8) + (packet[2] as u16);
                let bic = ((packet[3] as u16) << 8) + (packet[4] as u16);
                println!("Read Coil Status");
                println!("Reference Number: {}", rn);
                println!("Bit Count: {}", bic);
            }
        },
        2 => {
            if r_flag {
                let byc = packet[1];
                println!("Read Input Status Respons");
                println!("Byte Count: {}", byc);
                for i in 0 .. byc {
                    println!("data{}~{}: {:08b}"
                        ,i * 8, i * 8 + 7, packet[(2 + i) as usize]);
                }
            } else {
                let rn = ((packet[1] as u16) << 8) + (packet[2] as u16);
                let bic = ((packet[3] as u16) << 8) + (packet[4] as u16);
                println!("Read Input Status");
                println!("Reference Number: {}", rn);
                println!("Bit Count: {}", bic);
            }
        },
        3 => {
            if r_flag {
                let byc = packet[1];
                println!("Read Holding Register Respons");
                println!("Byte Count: {}", byc);
                for i in 0 .. (byc / 2 - 1){
                    println!("data{} : {},", i,
                      ((packet[(i * 2 + 2) as usize] as u16) << 8)
                     + (packet[(i * 2 + 3) as usize] as u16));
                }
            } else {
                let rn = ((packet[1] as u16) << 8) + (packet[2] as u16);
                let bic = ((packet[3] as u16) << 8) + (packet[4] as u16);
                println!("Read Holding Register");
                println!("Reference Number: {}", rn);
                println!("Bit Count: {}", bic);
            }
        },
        4 => {
            if r_flag {
                let byc = packet[1];
                println!("Read Input Register Respons");
                println!("Byte Count: {}", byc);
                for i in 0 .. (byc / 2 - 1){
                    println!("data{} : {},", i, 
                      ((packet[(i * 2 + 2) as usize] as u16) << 8)
                     + (packet[(i * 2 + 3) as usize] as u16));
                }
            } else {
                let rn = ((packet[1] as u16) << 8) + (packet[2] as u16);
                let bic = ((packet[3] as u16) << 8) + (packet[4] as u16);
                println!("Read Input Register");
                println!("Reference Number: {}", rn);
                println!("Bit Count: {}", bic);
            }
        },
        5 => {
            if r_flag {
                let n = ((packet[1] as u16) << 8) + (packet[2] as u16);
                let cd = ((packet[3] as u16) << 8) + (packet[4] as u16);
                println!("Force Single Coil Respons");
                println!("Number: {}", n);
                println!("Change Data: {}", cd);
            } else {
                let rn = ((packet[1] as u16) << 8) + (packet[2] as u16);
                let cd = ((packet[3] as u16) << 8) + (packet[4] as u16);
                println!("Force Single Coil");
                println!("Reference Number: {}", rn);
                println!("Change Data: {}", cd);
            }
        },
        6 => {
            if r_flag {
                let n = ((packet[1] as u16) << 8) + (packet[2] as u16);
                let cd = ((packet[3] as u16) << 8) + (packet[4] as u16);
                println!("Preset Single Register Respons");
                println!("Number: {}", n);
                println!("Change Data: {}", cd);
            } else {
                let n = ((packet[1] as u16) << 8) + (packet[2] as u16);
                let cd = ((packet[3] as u16) << 8) + (packet[4] as u16);
                println!("Preset Single Register");
                println!("Number: {}", n);
                println!("Change Data: {}", cd);
            }
        },
        8 => {
            if r_flag {
                let sc = ((packet[1] as u16) << 8) + (packet[2] as u16);
                let d = ((packet[3] as u16) << 8) + (packet[4] as u16);
                println!("Diagnostics Respons");
                println!("sub coder: {}", sc);
                println!("Data: {}", d);
            } else {
                let sc = ((packet[1] as u16) << 8) + (packet[2] as u16);
                let d = ((packet[3] as u16) << 8) + (packet[4] as u16);
                println!("Diagnostics");
                println!("sub code: {}", sc);
                println!("Data: {}", d);
            }
        },
        11 => {
            if r_flag {
                let s = ((packet[1] as u16) << 8) + (packet[2] as u16);
                let ec = ((packet[3] as u16) << 8) + (packet[4] as u16);
                println!("Fetch Communication Event Counter Respons");
                println!("Status: {}", s);
                println!("Event Counter: {}", ec);
            } else {
                println!("Fetch Communication Event Counter");
            }
        },
        12 => {
            if r_flag {
                let byc = packet [1];
                let s = ((packet[2] as u16) << 8) + (packet[3] as u16);
                let ec = ((packet[4] as u16) << 8) + (packet[5] as u16);
                let mc = ((packet[6] as u16) << 8) + (packet[7] as u16);
                println!("Fetch Communication Event Log Respons");
                println!("Byte Count: {}", byc);
                println!("Status: {}", s);
                println!("Event Counter: {}", ec);
                println!("Message Counter: {}", mc);
                for i in 8 .. packet.len(){
                    println!("event{}: {}", i - 8, packet[i]);
                }
            } else {
                println!("Fetch Communication Event Log");
            }
        },
        15 => {
            if r_flag {
                let rn = ((packet[1] as u16) << 8) + (packet[2] as u16);
                let bic = ((packet[3] as u16) << 8) + (packet[4] as u16);
                println!("Write Multiple Coils Respons");
                println!("Reference Number: {}", rn);
                println!("Bit Count: {}", bic);
            } else {
                let rn = ((packet[1] as u16) << 8) + (packet[2] as u16);
                let bic = ((packet[3] as u16) << 8) + (packet[4] as u16);
                let byc = packet[5];
                let mut data : usize= 0;
                for i in 6..(byc + 6) {
                    data = (data << 8) + (packet[i as usize] as usize);
                }
                println!("Write Multiple Coils");
                println!("Reference Number: {}", rn);
                println!("Bit Count: {}", bic);
                println!("Byte Count: {}", byc);
                println!("Data: {}", data);
            }
        },
        16 => {
            if r_flag {
                let rn = ((packet[1] as u16) << 8) + (packet[2] as u16);
                let rc = ((packet[3] as u16) << 8) + (packet[4] as u16);
                println!("Preset Multiple Registers Respons");
                println!("Reference Number: {}", rn);
                println!("Registers Count: {}", rc);
            } else {
                let rn = ((packet[1] as u16) << 8) + (packet[2] as u16);
                let rc = ((packet[3] as u16) << 8) + (packet[4] as u16);
                let byc = packet[5];
                println!("Preset Multiple Registers");
                println!("Reference Number: {}", rn);
                println!("Registers Count: {}", rc);
                for i in 0 .. (byc / 2 - 1){
                    println!("Change Data{} : {},", i + 1,
                      ((packet[(i * 2 + 6) as usize] as u16) << 8)
                     + (packet[(i * 2 + 7) as usize] as u16));
                }
            }
        },
        17 => {
            if r_flag {
                println!("Report Slave ID Respons");
            } else {
                println!("Report Slave ID");
            }

        },
        _ => {
            println!("error function");
        },
    }
    for p in packet.iter() {
        print!("{:02x} ", p);
    }
    println!();
}

fn handle_modbus_tcp(packet: &[u8], r_flag: bool) {
    let ti = ((packet[0] as u16) << 8) + (packet[1] as u16);
    let pi = ((packet[2] as u16) << 8) + (packet[3] as u16);
    let l  = ((packet[4] as u16) << 8) + (packet[5] as u16);
    let ui = packet[6];
    let ad = packet[7];
    println!("Transaction Identifier: {}", ti);
    println!("Protocol Identifier: {}", pi);
    println!("Length: {}", l);
    println!("Unit Identifier: {}", ui);
    println!("address: {}", ad);
    let end = packet.len();
    handle_modbus(&packet[7 .. end], r_flag);
}

fn handle_udp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        println!(
            "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
            interface_name,
            source,
            udp.get_source(),
            destination,
            udp.get_destination(),
            udp.get_length()
        );
    } else {
        println!("[{}]: Malformed UDP Packet", interface_name);
    }
}

fn handle_icmp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!(
                    "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                    interface_name,
                    source,
                    destination,
                    echo_reply_packet.get_sequence_number(),
                    echo_reply_packet.get_identifier()
                );
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                println!(
                    "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                    interface_name,
                    source,
                    destination,
                    echo_request_packet.get_sequence_number(),
                    echo_request_packet.get_identifier()
                );
            }
            _ => println!(
                "[{}]: ICMP packet {} -> {} (type={:?})",
                interface_name,
                source,
                destination,
                icmp_packet.get_icmp_type()
            ),
        }
    } else {
        println!("[{}]: Malformed ICMP Packet", interface_name);
    }
}

fn handle_icmpv6_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        println!(
            "[{}]: ICMPv6 packet {} -> {} (type={:?})",
            interface_name,
            source,
            destination,
            icmpv6_packet.get_icmpv6_type()
        );
    } else {
        println!("[{}]: Malformed ICMPv6 Packet", interface_name);
    }
}

fn handle_tcp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        println!(
            "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
            interface_name,
            source,
            tcp.get_source(),
            destination,
            tcp.get_destination(),
            packet.len()
        );
        let r_flag;
        if tcp.get_destination() == 502 {
            r_flag = false;
        } else {
            r_flag = true;
        }
        if tcp.payload().len() > 0{
            handle_modbus_tcp(tcp.payload(), r_flag);
        }
    } else {
        println!("[{}]: Malformed TCP Packet", interface_name);
    }
}

fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmpv6 => {
            handle_icmpv6_packet(interface_name, source, destination, packet)
        }
        _ => println!(
            "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
            interface_name,
            match source {
                IpAddr::V4(..) => "IPv4",
                _ => "IPv6",
            },
            source,
            destination,
            protocol,
            packet.len()
        ),
    }
}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
        );
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
        );
    } else {
        println!("[{}]: Malformed IPv6 Packet", interface_name);
    }
}

fn handle_arp_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = ArpPacket::new(ethernet.payload());
    if let Some(header) = header {
        println!(
            "[{}]: ARP packet: {}({}) > {}({}); operation: {:?}",
            interface_name,
            ethernet.get_source(),
            header.get_sender_proto_addr(),
            ethernet.get_destination(),
            header.get_target_proto_addr(),
            header.get_operation()
        );
    } else {
        println!("[{}]: Malformed ARP Packet", interface_name);
    }
}

fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket) {
    let interface_name = &interface.name[..];
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet),
        EtherTypes::Ipv6 => handle_ipv6_packet(interface_name, ethernet),
        EtherTypes::Arp => handle_arp_packet(interface_name, ethernet),
        _ => println!(
            "[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
            interface_name,
            ethernet.get_source(),
            ethernet.get_destination(),
            ethernet.get_ethertype(),
            ethernet.packet().len()
        ),
    }
}

fn main() {
    use pnet::datalink::Channel::Ethernet;

    let iface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            writeln!(io::stderr(), "USAGE: packetdump <NETWORK INTERFACE>").unwrap();
            process::exit(1);
        }
    };
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", iface_name));

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type:"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    loop {
        let mut buf: [u8; 1600] = [0u8; 1600];
        let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();
        match rx.next() {
            Ok(packet) => {
                let payload_offset;
                if cfg!(any(target_os = "macos", target_os = "ios"))
                    && interface.is_up()
                    && !interface.is_broadcast()
                    && ((!interface.is_loopback() && interface.is_point_to_point())
                        || interface.is_loopback())
                {
                    if interface.is_loopback() {
                        // The pnet code for BPF loopback adds a zero'd out Ethernet header
                        payload_offset = 14;
                    } else {
                        // Maybe is TUN interface
                        payload_offset = 0;
                    }
                    if packet.len() > payload_offset {
                        let version = Ipv4Packet::new(&packet[payload_offset..])
                            .unwrap()
                            .get_version();
                        if version == 4 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable());
                            continue;
                        } else if version == 6 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable());
                            continue;
                        }
                    }
                }
                handle_ethernet_frame(&interface, &EthernetPacket::new(packet).unwrap());
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
    }
}
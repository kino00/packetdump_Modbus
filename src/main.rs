extern crate pnet;
extern crate pnet_macros_support;

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

mod packet;
//use packet::modbus_tcp::{ModbusTCPPacket, FunctionFieldValues};
use packet::modbus_tcp::*;

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
        let modbus_tcp = ModbusTCPPacket::new(tcp.payload());
        if let Some(modbus_tcp) = modbus_tcp{
            match (tcp.get_source(), tcp.get_destination()) {
                ( _ , 502 ) => { /* (送信元, 送信先) Request */
                    match modbus_tcp.get_function() {
                        FunctionFieldValues::ReadCoilStatus => {
                            let m_packet = read_coil_status::request::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    read coil status({}) Request, Reference Number: {}, Bit Count: {}",
                                m_packet.get_function(),
                                m_packet.get_reference_number(),
                                m_packet.get_bit_count()
                            );
                        }
                        FunctionFieldValues::ReadInputStatus => {
                            let m_packet = read_input_status::request::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    read input status({}) Request, Reference Number: {}, Bit Count: {}",
                                m_packet.get_function(),
                                m_packet.get_reference_number(),
                                m_packet.get_bit_count()
                            );
                        }
                        FunctionFieldValues::ReadHoldingRegister => {
                            let m_packet = read_holding_register::request::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    read holding register({}) Request, Reference Number: {}, Bit Count: {}",
                                m_packet.get_function(),
                                m_packet.get_reference_number(),
                                m_packet.get_bit_count()
                            );
                        }
                        FunctionFieldValues::ReadInputRegister => {
                            let m_packet = read_input_register::request::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    read input register({}) Request, Reference Number: {}, Bit Count: {}",
                                m_packet.get_function(),
                                m_packet.get_reference_number(),
                                m_packet.get_bit_count()
                            );
                        }
                        FunctionFieldValues::ForceSingleCoil => {
                            let m_packet = force_single_coil::request::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    force single coil({}) Request, Reference Number: {}, Data: {}",
                                m_packet.get_function(),
                                m_packet.get_reference_number(),
                                m_packet.get_data()
                            );
                        }
                        FunctionFieldValues::PresetSingleRegister => {
                            let m_packet = preset_single_register::request::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    preset singe register({}) Request, Reference Number: {}, Data: {}",
                                m_packet.get_function(),
                                m_packet.get_reference_number(),
                                m_packet.get_data()
                            );
                        }
                        FunctionFieldValues::Diagnostics => {
                            let m_packet = diagnostics::request::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    diagnostics({}) Request, sub code: {}, Data: {}",
                                m_packet.get_function(),
                                m_packet.get_sub_code(),
                                m_packet.get_data()
                            );
                        }
                        FunctionFieldValues::FetchCommunicationEventCounter  => {
                            let m_packet = fetch_communication_event_counter::request::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    fetch conmmunication event counter({}) Request,",
                                m_packet.get_function(),
                            );
                        }
                        FunctionFieldValues::FetchCommunicationEventCounterLog  => {
                            let m_packet = fetch_communication_event_counter_log::request::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    fetch conmmunication event counter log({}) Request,",
                                m_packet.get_function(),
                            );
                        }
                        FunctionFieldValues::ForceMultipleCoils => {
                            let m_packet = force_multiple_coils::request::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    force multiple coils({}) Request, Reference Number: {}, Register Count: {}, Byte Count: {}, data: {:?}",
                                m_packet.get_function(),
                                m_packet.get_reference_number(),
                                m_packet.get_register_count(),
                                m_packet.get_byte_count(),
                                m_packet.get_data()
                            );
                        }
                        FunctionFieldValues::PresetMultipleRegisters => {
                            let m_packet = preset_multiple_registers::request::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    preset multiple registers({}) Request, Reference Number: {}, Register Count: {}, Byte Count: {}, data: {:?}",
                                m_packet.get_function(),
                                m_packet.get_reference_number(),
                                m_packet.get_register_count(),
                                m_packet.get_byte_count(),
                                m_packet.get_data()
                            );
                        }
                        FunctionFieldValues::ReportSlaveID  => {
                            let m_packet = report_slave_id::request::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    freport_slave_id({}) Request,",
                                m_packet.get_function(),
                            );
                        }
                        _ => {
                            println!(
                                "unknown function number for {:?} request",
                                modbus_tcp.get_function()
                            );
                        }
                    }
                }
                ( 502 , _ ) => { /* (送信元, 送信先) Reply */
                    match modbus_tcp.get_function() {
                        FunctionFieldValues::ReadCoilStatus => {
                            let m_packet = read_coil_status::reply::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    read coil status({}) Reply, Byte Count: {}, Data: {:?}",
                                m_packet.get_function(),
                                m_packet.get_byte_count(),
                                m_packet.get_data()
                            );
                        }
                        FunctionFieldValues::ReadInputStatus => {
                            let m_packet = read_input_status::reply::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    read input status({}) Reply, Byte Count: {}, Data: {:?}",
                                m_packet.get_function(),
                                m_packet.get_byte_count(),
                                m_packet.get_data()
                            );
                        }
                        FunctionFieldValues::ReadHoldingRegister => {
                            let m_packet = read_holding_register::reply::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    read holding register({}) Reply, Byte Count: {}, Data: {:?}",
                                m_packet.get_function(),
                                m_packet.get_byte_count(),
                                m_packet.get_data()
                            );
                        }
                        FunctionFieldValues::ReadInputRegister => {
                            let m_packet = read_input_register::reply::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    read input register({}) Reply, Byte Count: {}, Data: {:?}",
                                m_packet.get_function(),
                                m_packet.get_byte_count(),
                                m_packet.get_data()
                            );
                        }
                        FunctionFieldValues::ForceSingleCoil => {
                            let m_packet = force_single_coil::reply::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    force single coil({}) Reply, Reference Number: {}, Data: {}",
                                m_packet.get_function(),
                                m_packet.get_reference_number(),
                                m_packet.get_data()
                            );
                        }
                        FunctionFieldValues::PresetSingleRegister => {
                            let m_packet = preset_single_register::reply::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    preset singe register({}) Reply, Reference Number: {}, Data: {}",
                                m_packet.get_function(),
                                m_packet.get_reference_number(),
                                m_packet.get_data()
                            );
                        }
                        FunctionFieldValues::Diagnostics => {
                            let m_packet = diagnostics::reply::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    diagnostics({}) Reply, sub code: {}, Data: {}",
                                m_packet.get_function(),
                                m_packet.get_sub_code(),
                                m_packet.get_data()
                            );
                        }
                        FunctionFieldValues::FetchCommunicationEventCounter  => {
                            let m_packet = fetch_communication_event_counter::reply::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    fetch conmmunication event counter({}) Reply, status: {}, event counter: {}",
                                m_packet.get_function(),
                                m_packet.get_status(),
                                m_packet.get_event_counter()
                            );
                        }
                        FunctionFieldValues::FetchCommunicationEventCounterLog  => {
                            let m_packet = fetch_communication_event_counter_log::reply::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    fetch conmmunication event counter log({}) Reply, byte count: {}, status: {}, event counter: {}, message counter: {}, event: {:?}",
                                m_packet.get_function(),
                                m_packet.get_byte_count(),
                                m_packet.get_status(),
                                m_packet.get_event_counter(),
                                m_packet.get_message_counter(),
                                m_packet.get_data()
                            );
                        }
                        FunctionFieldValues::ForceMultipleCoils => {
                            let m_packet = force_multiple_coils::reply::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    force multiple coils({}) Reply, Reference Number: {}, data: {}",
                                m_packet.get_function(),
                                m_packet.get_reference_number(),
                                m_packet.get_data()
                            );
                        }
                        FunctionFieldValues::PresetMultipleRegisters => {
                            let m_packet = preset_multiple_registers::reply::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    preset multiple registers({}) Reply, Reference Number: {}, data: {}",
                                m_packet.get_function(),
                                m_packet.get_reference_number(),
                                m_packet.get_data()
                            );
                        }
                        FunctionFieldValues::ReportSlaveID  => {
                            let m_packet = report_slave_id::reply::ModbusPacket::new(tcp.payload()).unwrap();
                            println!(
                                "    freport_slave_id({}) Reply, payload: {:?}",
                                m_packet.get_function(),
                                m_packet.payload()
                            );
                        }
                        _ => {
                            println!(
                                "unknown function number for {:?} reply",
                                modbus_tcp.get_function()
                            );
                        }
                    }
                }
                ( _ , _ ) => { /* ModbusTCP以外の通信 */ }
            }
        } else { /* ModbusTCPの形式に当てはまらなかったパケット */ }
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
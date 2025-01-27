use std::{collections::{HashMap, HashSet}, io::{Error, Read, Write}, net::{IpAddr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream}, sync::Arc, thread};
use serde::{de::value::BytesDeserializer, Deserialize, Serialize};
use pnet::{self, datalink, packet::{ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket}, ipv4::Ipv4Packet, ipv6::Ipv6Packet, Packet}, util::MacAddr};
use pnet::datalink::Channel::Ethernet;

// #[derive(Debug, Hash, PartialEq, Eq, Clone)]
// struct IPMask {
//   ip_address: u128,
//   // Number of relevant leftmost bits
//   subnet_mask: Option<usize>,
// }

#[derive(Clone)]
pub(crate) enum Action {
  FORWARD((MacAddr, IpAddr)),
  DISCARD
}

// #[derive(Debug, Serialize, Deserialize, Clone)]
// pub enum RCRequest {
// 	ADDOUTPUTPORT(u16)
// }

#[derive(Clone)]
pub(crate) struct FlowTable {
  matches: HashMap<PacketInfo, Action>,
}

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub(crate) struct PacketInfo {

  pub source_ip_addr: IpAddr,
  pub dest_ip_addr: IpAddr,
  pub source_mac_addr: MacAddr,
  pub dest_mac_addr: MacAddr

}

impl FlowTable {
  pub fn get_match(&self, packet_info: &PacketInfo) -> Option<Action> {
    self.matches.get(packet_info).cloned()
  }

  pub fn new() -> Self {
    FlowTable {
      matches: HashMap::new()
    }
  }

  pub fn add_entry_to_flow_table(&mut self, packet_info: PacketInfo, action: Action) {
    self.matches.insert(packet_info, action);
  }

}

impl PacketInfo {

  pub fn new(packet: &EthernetPacket) -> Self {

    let (source_mac_addr, dest_mac_addr) = (packet.get_source(), packet.get_destination());

    let (source_ip_addr, dest_ip_addr): (IpAddr, IpAddr) = match packet.get_ethertype() {

      EtherTypes::Ipv4 => {
        if let Some(ipv4_packet) = Ipv4Packet::new(packet.payload()) {
          (IpAddr::V4(ipv4_packet.get_source()), IpAddr::V4(ipv4_packet.get_destination()))
        } else {
          panic!(":(")
        }
      },
      EtherTypes::Ipv6 => {
        if let Some(ipv6_packet) = Ipv6Packet::new(packet.payload()) {
          (IpAddr::V6(ipv6_packet.get_source()), IpAddr::V6(ipv6_packet.get_destination()))
        } else {
          panic!(":(")
        }
      },
      _ => panic!(":(")
    };

    return PacketInfo {
      dest_ip_addr,
      source_ip_addr,
      source_mac_addr,
      dest_mac_addr
    }


  }

}

#[derive(Clone)]
pub(crate) struct PacketSwitch {
  pub flow_table: FlowTable,
  // ip_address: u128,
	// Virtualized model of a router's output port
	// u16 key represents an output port and multicast by having potentially multiple other router IPs
	// connected by a single output port. u16 in IPaddr tuple represents "input" port of router where data should be sent
	// port_connections: HashMap<u16, HashSet<(IpAddr, u16)>>,
}

impl PacketSwitch {

  pub fn new(flow_table: FlowTable) -> Self {

    return PacketSwitch {
      flow_table
    }
  }

  pub fn listen_for_incoming_packets(self) {

    let self_arc = Arc::new(self);

    for interface in pnet::datalink::interfaces() {

        let (mut transmitter, mut receiver) = match pnet::datalink::channel(&interface, pnet::datalink::Config::default()) {
          Ok(Ethernet(transmitter, receiver)) => (transmitter, receiver),
          Ok(_) => panic!("*blows up*"),
          Err(e) => {
            println!("{e}");
            continue
          }
        };
  
        thread::spawn({
          let self_arc = Arc::clone(&self_arc);
          move || {
            let cloned_self = Arc::clone(&self_arc);
            loop {
              match receiver.next() {
                Ok(incoming_packet) => {

                  // println!("Payload received: {:?}", payload_str);

                  let packet = EthernetPacket::new(incoming_packet).unwrap();

                  // Debugging: Extract and parse the payload
                  let payload = packet.payload();
                  println!("Packet received! {:#?}", 
                  payload.iter().map(|u| char::from(*u)).collect::<String>());
                  let necessary_packet_information = PacketInfo::new(&packet);
                
                  match cloned_self.get_best_action_for_packet(necessary_packet_information, &packet) {
                    Action::DISCARD => continue,
                    Action::FORWARD((dest_mac_addr, dest_ip_addr)) => {
                      let mut buff = [0; 5000];
                      let mut new_packet = MutableEthernetPacket::new(&mut buff).expect("balls galore");
                      new_packet.set_payload(packet.packet());
                      new_packet.set_destination(dest_mac_addr);
                      new_packet.set_source(packet.get_destination());
                      match dest_ip_addr {
                        IpAddr::V4(_) => new_packet.set_ethertype(EtherTypes::Ipv4),
                        IpAddr::V6(_) => new_packet.set_ethertype(EtherTypes::Ipv6)
                      }
                      println!("{:?}", new_packet);
                      transmitter.send_to(new_packet.packet(), None);
                    }
                  }
                },
                Err(e) => panic!("There was an error: {}", e)
              }
            }
        }
      })
        .join()
        .expect("Balls");
    }
    
  }

  pub fn get_best_action_for_packet(&self, packet_info: PacketInfo, packet: &EthernetPacket) -> Action {

    // In future, update router config or counters for example
    if let Some(action) = self.flow_table.get_match(&packet_info) {
      action
    } else {
      // self.send_packet_to_rc(packet_info, &packet)
      Action::DISCARD
    }
  }

  fn send_packet_to_rc(&self, packet_info: PacketInfo, packet: &EthernetPacket) -> Action {
    todo!()
  }



}
pub mod packet_switch_actions;
pub mod flow_table;
use std::{collections::{HashMap, HashSet}, io::{Error, Read, Write}, net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream}, sync::{Arc, Mutex}, thread};
use etherparse::SlicedPacket;
use flow_table::FlowTable;
use packet_switch_actions::Action;

use crate::{packet_structs::{Packet, PacketMetaData}, remote_controller::RemoteControllerResponse, utils::convert_slice_to_string};

#[derive(Clone)]
pub struct PacketSwitch {
  flow_table: FlowTable,
  tcp_ports_to_listen_to: HashSet<u16>,
  rc_ip_addr: IpAddr,
  rc_port_to_connect_to: u16,
  known_packet_switch_addresses: HashSet<IpAddr>,
  // Maps a given frame's destination port to the packet metadata for use by the thread responsible for reading tcp streams
  sniffed_packet_metadata: HashMap<u16, PacketMetaData>
}

impl PacketSwitch {
  pub fn new_with_flow_table(flow_table: FlowTable, tcp_ports_to_listen_to: HashSet<u16>, rc_info: (IpAddr, u16)) -> Self {
    return PacketSwitch {
      flow_table,
      tcp_ports_to_listen_to,
      rc_ip_addr: rc_info.0,
      rc_port_to_connect_to: rc_info.1,
      known_packet_switch_addresses: HashSet::new(),
      sniffed_packet_metadata: HashMap::new()
    }
  }

  pub fn new_without_flow_table(tcp_ports_to_listen_to: HashSet<u16>, rc_info: (IpAddr, u16)) -> Self {

    return PacketSwitch {
      flow_table: FlowTable::new(),
      tcp_ports_to_listen_to,
      rc_ip_addr: rc_info.0,
      rc_port_to_connect_to: rc_info.1,
      known_packet_switch_addresses: HashSet::new(),
      sniffed_packet_metadata: HashMap::new()
    }
  }
  
  pub fn listen_for_incoming_packets(self) -> Result<(), Error> {

    let ports_to_listen_to = self.tcp_ports_to_listen_to.clone();

    let self_mut_ref = Arc::new(Mutex::new(self));
    let other_self_mut_ref = self_mut_ref.clone();

    thread::spawn(move || {
        
      for interface in pnet::datalink::interfaces() {
        let (_, mut rx) = match pnet::datalink::channel(&interface, pnet::datalink::Config::default()) {
          Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
          Ok(_) => panic!("Ah!"),
          Err(e) => panic!("{e}")
        };

        while let Ok(packet) = rx.next() {

          match SlicedPacket::from_ethernet(packet) {
            Ok(packet) => {

              let mut lock_on_self = self_mut_ref.try_lock();
              while let Err(_) = lock_on_self {
                lock_on_self = self_mut_ref.try_lock();
              }

              let mut lock_on_self = lock_on_self.unwrap();


              // We only sniff packets that are destined for a port this switch is actively listening to and don't collect metdata on
              // packets coming from known packet switches since metadata about the packet has already been collected
              // May want to change in future idk
              if lock_on_self.is_packet_destined_for_watched_port(&packet) && !lock_on_self.is_packet_from_known_packet_switch(&packet) {
                let packet_metadata = PacketMetaData::new(&packet)
                  .expect("Encountered error");

                lock_on_self.sniffed_packet_metadata.insert(packet_metadata.get_dest_port(), packet_metadata);
              }
            },
            Err(value) => panic!("{value}")
          }

        }

      }

    });

    for port in ports_to_listen_to {

      let self_mut_ref = other_self_mut_ref.clone();
    
      thread::spawn(move || -> Result<(), Error> {
      
        let listener = TcpListener::bind(String::from("localhost:") + &port.to_string())?;

        while let Ok((mut stream, socket_addr)) = listener.accept() {

          // 1500 bytes = max number of bytes of ethernet frame
          let mut buffered_stream = Vec::with_capacity(1500);
          stream.read_to_end(&mut buffered_stream)?;

          let mut lock_on_self = self_mut_ref.try_lock();
            
          while let Err(_) = lock_on_self {
            lock_on_self = self_mut_ref.try_lock();
          }

          let mut lock_on_self = lock_on_self.unwrap();

          if let Some(packet) = lock_on_self.parse_packet_from_a_known_packet_switch(&socket_addr, &buffered_stream) {
            lock_on_self.switch_from_packet(packet)?;
          } else {

            match lock_on_self.sniffed_packet_metadata.get(&port).cloned() {
              Some(packet_metadata) => {
                println!("Got a packet! {:?}", packet_metadata);
                lock_on_self.switch_from_stream(&packet_metadata, buffered_stream)?;
              },
              None => println!("Couldn't retrieve packet metadata")
            };

          stream.shutdown(std::net::Shutdown::Both)?;
          }
        }
        Ok(())
      })
      .join()
      .expect("Failed to join thread")
      .expect("There was an error");
    }
  Ok(())
  }

  fn switch_from_packet(&mut self, packet: Packet) -> Result<(), Error> {

    let packet_metadata = packet.get_metadata();
    let mut action_to_take = self.flow_table.get_action_from_match(&packet.get_metadata());
    loop {
      match action_to_take {
        Action::FORWARDTOROUTER((ip_addr, dest_port)) => {
          println!("Attempting to forward!");

          // Perform better error handling such as forwarding to RC in case of error in future
          let mut stream_to_router = TcpStream::connect((ip_addr, dest_port))?;
          stream_to_router.write(&serde_json::to_vec(&packet)?)?;
          stream_to_router.flush()?;
          stream_to_router.shutdown(Shutdown::Both)?;
          break;
        },
        Action::FORWARDTODESTINATIONHOST((ip_addr, dest_port)) => {
          let mut stream_to_destination_host = TcpStream::connect((ip_addr, dest_port))?;
          stream_to_destination_host.write_all(packet.get_payload())?;
          stream_to_destination_host.flush()?;
          stream_to_destination_host.shutdown(Shutdown::Both)?;
          break;
        },
        Action::DISCARD => {
          // Do nothing with the packet and gracefully terminate session
          println!("Terminating session");
          break;
        },
        Action::FORWARDTORC => {
          action_to_take = self.forward_packet_to_remote_controller(&packet_metadata)
            .expect("Couldn't forward packet to RC");
          println!("New action to take: {action_to_take:?}");
        },
      };
    }
    Ok(())
  }

  fn switch_from_stream(&mut self, packet_metadata: &PacketMetaData, buffered_stream: Vec<u8>) -> Result<(), Error> {

    let mut action_to_take = self.flow_table.get_action_from_match(&packet_metadata);
    println!("packet message: {:?}, action to take: {:?}", convert_slice_to_string(&buffered_stream), action_to_take);

    // Can potentially get stuck in loop, should use bounds checking at RC to tell switch to discard packets after certain number
    // of routing attempts
    loop {
      match action_to_take {
        Action::FORWARDTOROUTER((ip_addr, u16)) => {
          let packet = Packet::new(&packet_metadata, &buffered_stream);
          println!("Attempting to forward!");

          // Perform better error handling such as forwarding to RC in case of error in future
          let mut stream_to_router = TcpStream::connect((ip_addr, u16))?;
          stream_to_router.write(&serde_json::to_vec(&packet)?)?;
          stream_to_router.flush()?;
          stream_to_router.shutdown(Shutdown::Both)?;
          break;
        },
        Action::FORWARDTODESTINATIONHOST((ip_addr, dest_port)) => {
          let mut stream_to_destination_host = TcpStream::connect((ip_addr, dest_port))?;
          stream_to_destination_host.write_all(&buffered_stream)?;
          stream_to_destination_host.flush()?;
          stream_to_destination_host.shutdown(Shutdown::Both)?;
          break;
        },
        Action::DISCARD => {
          // Do nothing with the packet and gracefully terminate session
          println!("Terminating session");
          break;
        },
        Action::FORWARDTORC => {
          action_to_take = self.forward_packet_to_remote_controller(&packet_metadata)
            .expect("Couldn't forward packet to RC");
          println!("New action to take: {action_to_take:?}");
        },
      };
    }
    Ok(())
  }
  
  fn is_packet_destined_for_watched_port(&self, packet: &SlicedPacket) -> bool {
    if let Some(transport_information) = &packet.transport {
      match transport_information {
        etherparse::TransportSlice::Tcp(tcp_header) => {
          if self.tcp_ports_to_listen_to.contains(&tcp_header.destination_port()) {
            return true
          }
        },
        _ => ()
      }
    }
    return false;
  }

  fn is_packet_from_known_packet_switch(&self, packet: &SlicedPacket) -> bool {
    if let Some(network_information) = &packet.net {
      match network_information {
        etherparse::NetSlice::Ipv4(ipv4_slice) => {
          return self.known_packet_switch_addresses.contains(&IpAddr::V4(ipv4_slice.header().source_addr()));
        },
        etherparse::NetSlice::Ipv6(ipv6_slice) => {
          return self.known_packet_switch_addresses.contains(&IpAddr::V6(ipv6_slice.header().source_addr()));
        },
        etherparse::NetSlice::Arp(_) => (),
      }
    }
    return false;
  }

  fn parse_packet_from_a_known_packet_switch(&self, addr: &SocketAddr, stream: &[u8]) -> Option<Packet> {
    if self.known_packet_switch_addresses.contains(&addr.ip()) {
      let packet = serde_json::from_slice::<Packet>(stream).ok();
      return packet;
    };
    return None;
  }
  
  fn forward_packet_to_remote_controller(&mut self, packet_metadata: &PacketMetaData) -> Result<Action, Error> {

    let mut stream = TcpStream::connect(self.rc_ip_addr.to_string() +":" +&self.rc_port_to_connect_to.to_string())?;
    let packet_as_json = serde_json::to_vec(&packet_metadata)?;
    stream.write_all(&packet_as_json)?;

    stream.flush()?;
    stream.shutdown(Shutdown::Write)?;

    let mut response_from_server = Vec::new();
    stream.read_to_end(&mut response_from_server)?;

    let response = serde_json::from_slice::<RemoteControllerResponse>(&response_from_server)?;

    match response {
      RemoteControllerResponse::FLOWTABLEUPDATED(updated_flow_table, action) => {
        self.update_flow_table(updated_flow_table);
        return Ok(action);
      }
    }

  }

  fn update_flow_table(&mut self, flow_table: FlowTable) {
    self.flow_table = flow_table;
  }

}

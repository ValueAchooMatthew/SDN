use std::net::IpAddr;
use serde::{Serialize, Deserialize};

use crate::structs::RCRequest;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Packet {
  destination_address: IpAddr,
  source_address: IpAddr,
  payload: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PacketWrapper {
  // Current router address and port
  source_router_address: IpAddr,
  output_port: u16,
  // Next router address and port
  destination_router_address: IpAddr,
  input_port: u16,
  rc_request: Option<RCRequest>,
  packet: Packet
}

impl PacketWrapper {
  pub fn new(packet: Packet, source_router_information: (IpAddr, u16), destination_router_information: (IpAddr, u16), rc_request: Option<RCRequest>) -> Self {
    PacketWrapper {
      source_router_address: source_router_information.0,
      output_port: source_router_information.1,
      destination_router_address: destination_router_information.0,
      input_port: destination_router_information.1,
      rc_request,
      packet
    }
  }

  pub fn get_inner_packet(&self) -> &Packet {
    &self.packet
  }

  pub fn get_source_router_address(&self) -> IpAddr {
    self.source_router_address
  }

  pub fn get_destination_router_information(&self) -> IpAddr {
    self.destination_router_address
  }
 
}

impl Packet {
  pub fn get_destination_address(&self) -> IpAddr {
    self.destination_address
  }
}



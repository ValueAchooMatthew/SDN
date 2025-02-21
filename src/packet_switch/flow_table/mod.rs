use crate::packet_structs::PacketMetaData;
use super::packet_switch_actions::Action;
use std::{collections::HashMap, net::IpAddr};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

#[serde_as]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
// Need to change in future
pub struct FlowTable {
  #[serde_as(as = "HashMap<DisplayFromStr, _>")]
  matches: HashMap<PacketMetaData, Action>,
}

impl FlowTable {
  pub fn get_action_from_match(&self, packet_info: &PacketMetaData) -> Action {

    // If the unlikely event that given packet metadata matches an instruction in the flowtable,
    // We just perform that action
    if let Some(action) = self.matches.get(packet_info) {
      return action.clone();
    }

    // To keep things simple we're only going to implement match plus action based on destination IP 
    // Technically stupid but whatever

    return self.get_best_destination_ip_address_action(&packet_info.get_dest_ip_addr());
  }

  fn get_best_destination_ip_address_action(&self, ip_addr: &IpAddr) -> Action {

    let mut greatest_number_of_bit_matches = 0;
    let mut best_matched_action = Action::FORWARDTORC;


    for entry in self.matches.keys() {

      let bit_matches = self.get_number_of_leading_matching_bits_of_ip_addresses(&entry.get_dest_ip_addr(), ip_addr);

      if bit_matches > greatest_number_of_bit_matches {
        greatest_number_of_bit_matches = bit_matches;
        best_matched_action = self.matches.get(entry).unwrap().clone();
      }

    }

    return best_matched_action;
  }

  fn get_number_of_leading_matching_bits_of_ip_addresses(&self, addr_1: &IpAddr, addr_2: &IpAddr) -> u32 {

    // We only compare IP addresses of the same protocol
    if let (IpAddr::V4(addr_1), IpAddr::V4(addr_2)) = (addr_1, addr_2) {
      
      let mask = addr_1.to_bits() ^ addr_2.to_bits();
      // The first digit of the mask equaling one is the first digit pair in each ip address that differ. Thus all bits to the left
      // Of that one match and the total number of bits to the left gives us the 
      return mask.leading_zeros();


    } else if let (IpAddr::V6(addr_1), IpAddr::V6(addr_2)) = (addr_1, addr_2) {

      let mask = addr_1.to_bits() ^ addr_2.to_bits();
      // The first digit of the mask equaling one is the first digit pair in each ip address that differ. Thus all bits to the left
      // Of that one match and the total number of bits to the left gives us the
      return mask.leading_zeros();
      
    }
    
    return 0;
  }

  pub fn new() -> Self {
    FlowTable {
      matches: HashMap::new()
    }
  }

  pub fn add_entry_to_flow_table(&mut self, packet_info: PacketMetaData, action: Action) {
    self.matches.insert(packet_info, action);
  }

}
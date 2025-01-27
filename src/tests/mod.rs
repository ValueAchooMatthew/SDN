#[cfg(test)]
mod tests {
  use std::net::Ipv4Addr;
  use pnet::util::MacAddr;
  use crate::structs::Action;
  use crate::structs::PacketInfo; 
  use crate::structs::PacketSwitch;
  use crate::structs::FlowTable;

  #[test]
  fn it_works() {
    let mut ft = FlowTable::new();
    ft.add_entry_to_flow_table(
      PacketInfo {
        source_ip_addr: std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        dest_ip_addr: std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        source_mac_addr: MacAddr::new(0, 0, 0, 0, 0, 0),
        dest_mac_addr: MacAddr::new(0, 0, 0, 0, 0, 0)
      },
      Action::FORWARD((MacAddr::new(0, 0, 0, 0, 0, 0), 
      std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))))
    );
    let ps = PacketSwitch::new(ft);
    ps.listen_for_incoming_packets();
  }

}
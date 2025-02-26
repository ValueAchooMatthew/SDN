#[cfg(test)]


mod tests {
  use std::collections::HashSet;
  use std::fs::File;  
  use std::net::IpAddr;
  use std::net::Ipv4Addr;
  use simplelog::WriteLogger;
  use crate::packet_switch::PacketSwitch;
  extern crate simplelog;

  #[test]
  fn it_works() {
    let log_file = File::create("logbybolbs.txt").unwrap();
    WriteLogger::init(simplelog::LevelFilter::max(), simplelog::Config::default(), log_file).unwrap();

    let ps = PacketSwitch::new_without_flow_table(
      HashSet::from([9003]), 
      (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 165)), 9003)   
    );

    ps.listen_for_incoming_packets()
      .expect("Aah!");
  }
}
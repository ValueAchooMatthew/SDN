#[cfg(test)]
mod tests {
  use std::collections::HashSet;
  use std::net::IpAddr;
  use std::net::Ipv4Addr;
  use std::thread;

  use crate::packet_switch::PacketSwitch;
  use crate::remote_controller::RemoteController;

  #[test]
  fn it_works() {
    let ps = PacketSwitch::new_without_flow_table(
      HashSet::from([9000]), 
      (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9001)
    );

    let rc = RemoteController::new(HashSet::from([9001]));

    thread::spawn(move || {
      ps.listen_for_incoming_packets()
      .expect("Aah!");
    });

    thread::spawn(move || {
      rc.listen_for_packet_switch_requests()
      .expect("Yikes!");
    })
    .join()
    .expect("Ah!");


  }

}
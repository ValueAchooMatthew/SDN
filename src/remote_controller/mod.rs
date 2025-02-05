use std::{collections::{HashMap, HashSet}, io::{Error, Read, Write}, net::{IpAddr, Shutdown, TcpListener}, sync::{Arc, Mutex}, thread};

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::packet_switch::{FlowTable, PacketMetaData, Action};

#[derive(Clone, Debug)]
pub struct RemoteController {
  current_packet_switch_flow_tables: HashMap<IpAddr, FlowTable>,
  direct_packet_switch_connections: HashMap<IpAddr, HashSet<IpAddr>>, 
  ports_to_listen_to: HashSet<u16>
  // Port that new routers wanting to be controlled by the given RC must connect to
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub enum RemoteControllerResponse {
  FLOWTABLEUPDATED(FlowTable, Action),
}

impl RemoteController {

  pub fn new(ports_to_listen_to: HashSet<u16>) -> Self {
    RemoteController {
      current_packet_switch_flow_tables: HashMap::new(),
      direct_packet_switch_connections: HashMap::new(),
      ports_to_listen_to: ports_to_listen_to
    }
  }

  fn add_switch_to_rc(&mut self, packet_switch_ip_address: IpAddr) {

    self
      .current_packet_switch_flow_tables
      .insert(packet_switch_ip_address, FlowTable::new());

  }

  pub fn listen_for_packet_switch_requests(self) -> Result<(), Error> {

    for port in &self.ports_to_listen_to {
      
      let port = port.clone();
      let self_ref = Arc::new(Mutex::new(self.clone()));

      thread::spawn(move || -> Result<(), Error> {

        let listener = TcpListener::bind(String::from("localhost:") +&port.to_string())?;
        
        while let Ok((mut stream, socket)) = listener.accept() {
          
          let mut message_from_packet_switch = Vec::with_capacity(1500);
          stream.read_to_end(&mut message_from_packet_switch)?;
          let packet_metadata = serde_json::from_slice::<PacketMetaData>(&message_from_packet_switch)?;

          let mut lock = self_ref.try_lock();
          
          while let Err(_) = lock {
            lock = self_ref.try_lock();
          }

          let mut self_ref = lock.unwrap();

          if let Some(ip_addr_of_connected_router) = self_ref.does_any_packet_switch_connect_directly_to_ip_addr(&packet_metadata) {

            let updated_ps_flow_table = self_ref.current_packet_switch_flow_tables
              .entry(socket.ip())
              .and_modify(|ft| {
                ft.add_entry_to_flow_table(packet_metadata.clone(), Action::FORWARD(ip_addr_of_connected_router));
              })
              .or_insert_with(|| {
                let mut ft = FlowTable::new();
                ft.add_entry_to_flow_table(packet_metadata, Action::FORWARD(ip_addr_of_connected_router));
                return ft;
              });

              let ft_as_vec = serde_json::to_vec(
                &RemoteControllerResponse::FLOWTABLEUPDATED(
                  updated_ps_flow_table.clone(), 
                  Action::DISCARD)
              )?;

              stream.write_all(&ft_as_vec)?;
              stream.flush()?;
              stream.shutdown(Shutdown::Both)?;

          } else {

            let updated_ps_flow_table = self_ref.current_packet_switch_flow_tables
            .entry(socket.ip())
            .and_modify(|ft| {
              ft.add_entry_to_flow_table(packet_metadata.clone(), Action::FORWARD(packet_metadata.get_dest_ip_addr()));
            })
            .or_insert_with(|| {
              let mut ft = FlowTable::new();
              ft.add_entry_to_flow_table(packet_metadata.clone(), Action::FORWARD(packet_metadata.get_dest_ip_addr()));
              return ft;
            });

            let ft_as_vec = serde_json::to_vec(
              &RemoteControllerResponse::FLOWTABLEUPDATED(
                updated_ps_flow_table.clone(), 
                Action::DISCARD)
              )?;

            stream.write_all(&ft_as_vec)?;
            stream.flush()?;
            stream.shutdown(Shutdown::Both)?;

          }

        };

        Ok(())
      })
      .join()
      .expect("Couldn't join thread")?;

    };

    Ok(())

  }

  // Change to find router with best number of hops instead of just direct connections for robustness in future
  fn does_any_packet_switch_connect_directly_to_ip_addr(&self, metadata: &PacketMetaData) -> Option<IpAddr> {
    for (packet_switch_ip, ip_address_of_direct_connection) in &self.direct_packet_switch_connections {
      if ip_address_of_direct_connection.contains(&metadata.get_source_ip_addr()) {
        Some(packet_switch_ip.clone());
      }
    }
    None
  }


}

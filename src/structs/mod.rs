use std::{collections::{HashMap, HashSet}, io::{Error, Read, Write}, net::{IpAddr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream}, thread};
use serde::{de::value::BytesDeserializer, Deserialize, Serialize};
use super::protocol::{Packet, PacketWrapper};

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct IPMask {
  ip_address: u128,
  // Number of relevant leftmost bits
  subnet_mask: Option<usize>,
}

#[derive(Clone)]
enum Action {
  // u32 corresponds to the port number to forward out of
  FORWARD(u16),
  DISCARD,
  SENDTORC(RCRequest)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RCRequest {
	ADDOUTPUTPORT(u16)
}

#[derive(Clone)]
struct FlowTable {
  matches: HashMap<IPMask, Action>,
}

#[derive(Clone)]
pub struct PacketSwitch {
  flow_table: FlowTable,
  rc_information: (IpAddr, u16),
  ip_address: u128,
	// Virtualized model of a router's output port
	// u16 key represents an output port and multicast by having potentially multiple other router IPs
	// connected by a single output port. u16 in IPaddr tuple represents "input" port of router where data should be sent
	port_connections: HashMap<u16, HashSet<(IpAddr, u16)>>,
	input_ports_to_listen_to: HashSet<u16>
}

impl IPMask {

  pub fn new(addr: IpAddr, subnet_mask: Option<usize>) -> Self {
    IPMask {
      ip_address: match addr {
        IpAddr::V4(addr) => {<u32 as Into<u128>>::into(addr.to_bits()) << 96}
        IpAddr::V6(addr) => addr.to_bits()
      },
      subnet_mask
    }
  }


  pub fn does_addr_match_mask(&self, addr: IPMask) -> bool {
    if let Some(mask_size) = self.subnet_mask {
      let bitwise_xord_mask = self.ip_address ^ addr.ip_address;
      // We need the first mask_size number of bits to be equal to zero for this address to match
      // therefore, the number produced must be less than or equal to binary number equal to all 1's except for a number
      // of leading zeros equal to the size of the subnet mask in bits
    
		  if bitwise_xord_mask > 2_u128.pow(128 - <usize as TryInto<u32>>::try_into(mask_size).unwrap()) - 1 {
        return false;
      }
      
      return true;
    
		} else {
      return self.ip_address == addr.ip_address
    }
  }
}

impl PacketSwitch {

  pub fn listen(&self) -> Result<(), Error> {

		for port in self.input_ports_to_listen_to.clone() {
			
			let switch = self.clone();

			thread::spawn(move || -> Result<(), Error> {
				let listener = TcpListener::bind(SocketAddr::new([127, 0, 0, 1].into(), port))?;
				for stream in listener.incoming() {
					if let Ok(stream) = stream {

            let stream_as_bytes: Result<Vec<u8>, Error> = stream.bytes().collect();

            match PacketWrapper::deserialize(
              BytesDeserializer::<serde::de::value::Error>::new(&stream_as_bytes?)
            ) {
              Ok(wrapper) => {
              // let current_router_information = (port)
                let inner_packet = wrapper.get_inner_packet().clone();
                switch.act_on_packet(inner_packet)?;
                
              },
              Err(err) => todo!("{err:?}")
            }
            

          }
				}
				Ok(())
			});
		}

		Ok(())
  
  }

  // Always returns addresses as Ipv6, since ipv6 better lol
  pub fn get_address_as_ip_addr(&self) -> IpAddr {
    return IpAddr::V6(Ipv6Addr::from(self.ip_address));
  }

  pub fn act_on_packet(&self, inner_packet: Packet) -> Result<(), Error> {

    // if packet.ttl().is_err() || packet.ttl().is_ok_and(|ttl| ttl == 0) {
    //   // Effectively discards packet
    //   return Ok(());
    // }

    let most_relevant_action = self
			.flow_table
			.get_most_relevant_action(&inner_packet.get_destination_address());

		if let Some(action_to_take) = most_relevant_action {
			match action_to_take {
				Action::FORWARD(port_to_forward_out_of) => {

					let possible_packet_switches_to_forward_packet_to = self.port_connections
						.get(&port_to_forward_out_of);

					if let Some(possible_routers) = possible_packet_switches_to_forward_packet_to {

						// Must handle condition where hashset is empty in future
						let pseudo_random_first_router: &(IpAddr, u16) = possible_routers.into_iter().next().unwrap();
            let source_router_information = (self.get_address_as_ip_addr(), port_to_forward_out_of);
						self.forward_packet_to_router(inner_packet, &source_router_information, pseudo_random_first_router)?;

					} else {
						// If this happens there is something wrong with the router's flowtable and should be reset
						self.forward_packet_to_rc(inner_packet, RCRequest::ADDOUTPUTPORT(port_to_forward_out_of))?;

					}

				}
				// We just do nothing with the packet
				Action::DISCARD => (),
				// 
				Action::SENDTORC(request) => {
          self.forward_packet_to_rc(inner_packet, request)?;
        },

      }

		} else {
			// We don't know how to handle the packet, forward to RC
			TcpStream::connect(self.rc_information)?;
		}
		Ok(())
  }

  // source router info = router IP, output port
  // dest router info = router IP, input port
	pub fn forward_packet_to_router(&self, packet: Packet, source_router_information: &(IpAddr, u16), destination_router_information: &(IpAddr, u16)) -> Result<(), Error> {

    let mut stream = TcpStream::connect(destination_router_information)?;

    let packet_wrapper_as_bytes = serde_json::to_vec(
      &PacketWrapper::new(packet, *source_router_information, *destination_router_information, None)
    )
    .expect("Balls");
    
    stream.write_all(
      &packet_wrapper_as_bytes
    )?;

    stream.flush()?;
    // Explicitly close the connection (graceful shutdown)
    stream.shutdown(Shutdown::Both)?;

    Ok(())
	}

	pub fn forward_packet_to_rc(&self, packet: Packet, request: RCRequest) -> Result<(), Error> {

    let mut stream = TcpStream::connect(self.rc_information)?;

    let packet_wrapper_as_bytes = serde_json::to_vec(
      &PacketWrapper::new(packet, (self.get_address_as_ip_addr(), 32), self.rc_information, Some(request))
    )
    .expect("Balls");

    stream.write_all(
      &packet_wrapper_as_bytes
    )?;

    stream.flush()?;
    // Explicitly close the connection (graceful shutdown)
    stream.shutdown(Shutdown::Both)?;

    Ok(())

	}

}

impl FlowTable {

  pub fn get_most_relevant_action(&self, addr: &IpAddr) -> Option<Action> {
    let mut match_found = false;
    let mut length_of_longest_match = None;
    let mut best_match: Option<Action> = None;
    for (mask, action) in &self.matches {
      if mask.does_addr_match_mask(IPMask::new(addr.to_owned(), None)) {
        if !match_found {
          length_of_longest_match = mask.subnet_mask;
          match_found = true;
          best_match = Some(action.clone());
        
        } else if let Some(length_of_subnet_mask) = mask.subnet_mask {
          if let Some(length) = length_of_longest_match {
            if length_of_subnet_mask > length {
              length_of_longest_match = Some(length);
              best_match = Some(action.clone());
            }
          }
        }
      }
    }
    best_match
  } 
}
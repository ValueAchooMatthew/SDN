use crate::utils::parse_string_to_mac_addr;
use std::{fmt, net::IpAddr, str::FromStr};
use etherparse::SlicedPacket;
use serde::{Deserialize, Serialize};


// Add transport protocol field in future
#[derive(Clone, Hash, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct PacketMetaData {
  source_ip: IpAddr,
  dest_ip: IpAddr,
  source_mac: [u8; 6],
  dest_mac: [u8; 6],
  source_port: u16,
  dest_port: u16,
}

#[derive(Debug)]
pub enum PacketMetaDataErrors {
  UNSUPPORTEDTRANSPORTPROTOCOL,
  UNABLETOPARSETRANSPORTHEADERS,
  UNSUPPORTEDNETWORKPROTOCOL,
  UNABLETOPARSENETWORKPROTOCOLHEADERS,
  UNSUPPORTEDLINKLAYERPROTOCOL,
  UNABLETOPARSELINKLAYERPROTOCOLHEADERS,
  COULDNTPARSEFROMSTRING
}

impl PacketMetaData {
  pub fn new(packet: &SlicedPacket) -> Result<Self, PacketMetaDataErrors> {

    let source_port;
    let dest_port;
    let source_ip;
    let dest_ip;
    let source_mac;
    let dest_mac;

    // Add support for UDP later
    if let Some(transport_information) = &packet.transport {
      match transport_information {
        etherparse::TransportSlice::Tcp(tcp_header) => {
          dest_port = tcp_header.destination_port();
          source_port = tcp_header.source_port();
        },
        _ => {
          return Err(PacketMetaDataErrors::UNSUPPORTEDTRANSPORTPROTOCOL);
        }
      }
    } else {
      return Err(PacketMetaDataErrors::UNABLETOPARSETRANSPORTHEADERS);
    }

    if let Some(network_information) = &packet.net {
      match network_information {
        etherparse::NetSlice::Ipv4(network_header) => {
          source_ip = IpAddr::V4(network_header.header().source_addr());
          dest_ip = IpAddr::V4(network_header.header().destination_addr());
        },
        etherparse::NetSlice::Ipv6(network_header) => {
          source_ip = IpAddr::V6(network_header.header().source_addr());
          dest_ip = IpAddr::V6(network_header.header().destination_addr());
        },
        _ => {
          return Err(
            PacketMetaDataErrors::UNSUPPORTEDNETWORKPROTOCOL
          )
        }
      }
    } else {
      return Err(
        PacketMetaDataErrors::UNABLETOPARSENETWORKPROTOCOLHEADERS
      )
    }

    if let Some(link_layer_information) = &packet.link {
      match link_layer_information {
        etherparse::LinkSlice::Ethernet2(ethernet2_header) => {
          source_mac = ethernet2_header.source();
          dest_mac = ethernet2_header.destination();
        },
        _ => {
          return Err(PacketMetaDataErrors::UNSUPPORTEDLINKLAYERPROTOCOL)
        }
      }
    } else {
      return Err(
        PacketMetaDataErrors::UNABLETOPARSELINKLAYERPROTOCOLHEADERS
      )
    }

    return Ok(PacketMetaData {
      dest_ip,
      source_ip,
      source_mac,
      dest_mac,
      source_port,
      dest_port
    })

  }


  pub fn get_dest_port(&self) -> u16 {
    return self.dest_port;
  }

  pub fn get_source_ip_addr(&self) -> IpAddr {
    return self.source_ip;
  }

  pub fn get_dest_ip_addr(&self) -> IpAddr {
    return self.dest_ip;
  }

}


impl fmt::Display for PacketMetaData {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "{}:{}-{}:{}-{:02X?}-{:02X?}",
      self.source_ip, self.source_port, self.dest_ip, self.dest_port,
      self.source_mac, self.dest_mac
    )
  }
}

impl FromStr for PacketMetaData {

  type Err = PacketMetaDataErrors;

  fn from_str(s: &str) -> Result<Self, PacketMetaDataErrors> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 4 {
      return Err(PacketMetaDataErrors::COULDNTPARSEFROMSTRING);
    }
    let source_ip_port: Vec<&str> = parts[0].split(':').collect();
    let dest_ip_port: Vec<&str> = parts[1].split(':').collect();

    if source_ip_port.len() != 2 || dest_ip_port.len() != 2 {
      return Err(PacketMetaDataErrors::COULDNTPARSEFROMSTRING);
    }

    let source_ip = source_ip_port[0].parse().map_err(|_| PacketMetaDataErrors::COULDNTPARSEFROMSTRING)?;
    let source_port = source_ip_port[1].parse().map_err(|_| PacketMetaDataErrors::COULDNTPARSEFROMSTRING)?;
    let dest_ip = dest_ip_port[0].parse().map_err(|_| PacketMetaDataErrors::COULDNTPARSEFROMSTRING)?;
    let dest_port = dest_ip_port[1].parse().map_err(|_| PacketMetaDataErrors::COULDNTPARSEFROMSTRING)?;
    let source_mac = parse_string_to_mac_addr(parts[2]).map_err(|_| PacketMetaDataErrors::COULDNTPARSEFROMSTRING)?;
    let dest_mac = parse_string_to_mac_addr(parts[3]).map_err(|_| PacketMetaDataErrors::COULDNTPARSEFROMSTRING)?;

    Ok(PacketMetaData {
        source_ip,
        dest_ip,
        source_mac: source_mac.into(),
        dest_mac: dest_mac.into(),
        source_port,
        dest_port,
    })
  }

}

impl fmt::Display for PacketMetaDataErrors {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
        PacketMetaDataErrors::UNSUPPORTEDTRANSPORTPROTOCOL => write!(f, "UNSUPPORTEDTRANSPORTPROTOCOL"),
        PacketMetaDataErrors::UNABLETOPARSETRANSPORTHEADERS => write!(f, "UNABLETOPARSETRANSPORTHEADERS"),
        PacketMetaDataErrors::UNSUPPORTEDNETWORKPROTOCOL => write!(f, "UNSUPPORTEDNETWORKPROTOCOL"),
        PacketMetaDataErrors::UNABLETOPARSENETWORKPROTOCOLHEADERS => write!(f, "UNABLETOPARSENETWORKPROTOCOLHEADERS"),
        PacketMetaDataErrors::UNSUPPORTEDLINKLAYERPROTOCOL => write!(f, "UNSUPPORTEDLINKLAYERPROTOCOL"),
        PacketMetaDataErrors::UNABLETOPARSELINKLAYERPROTOCOLHEADERS => write!(f, "UNABLETOPARSELINKLAYERPROTOCOLHEADERS"),
        PacketMetaDataErrors::COULDNTPARSEFROMSTRING => write!(f, "COULDNTPARSEFROMSTRING")
    }
  }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Packet {
  metadata: PacketMetaData,
  payload: Vec<u8>
}

impl Packet {
  pub fn new(metadata: &PacketMetaData, payload: &Vec<u8>) -> Self {
    Packet {
      metadata: metadata.clone(),
      payload: payload.clone()
    }
  }
  
  pub fn get_metadata(&self) -> &PacketMetaData {
    &self.metadata
  }

  pub fn get_payload(&self) -> &[u8] {
    &self.payload
  }

}
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum Action {
  FORWARDTOROUTER((IpAddr, u16)),
  FORWARDTODESTINATIONHOST((IpAddr, u16)),
  DISCARD,
  FORWARDTORC
}

use pnet::util::MacAddr;

// Fix later to work with error I actually cannot be bothered rn
pub fn parse_string_to_mac_addr(str: &str) -> Result<MacAddr, ()> {

  let str_without_brackets = &str[1..str.len() - 1];

  let numbers: Vec<u8> = str_without_brackets.split(",").map(|s| s.trim().parse::<u8>().unwrap()).collect();

  Ok(MacAddr::new(
  *numbers.get(0).unwrap(), 
  *numbers.get(1).unwrap(), 
  *numbers.get(2).unwrap(), 
  *numbers.get(3).unwrap(), 
  *numbers.get(4).unwrap(), 
  *numbers.get(5).unwrap()
  ))
} 

// Only works for UTF-8 encoded data
pub fn convert_slice_to_string(slice: &[u8]) -> String {
  slice.into_iter().map(|b| char::from(*b)).collect::<String>()
}
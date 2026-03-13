package main

# Decode the embedded JSON string
open_sg = decoded {
  input.resource_changes[_].change.after.triggers["open_sg"] != ""
  json.unmarshal(input.resource_changes[_].change.after.triggers["open_sg"], decoded)
}

# Deny if any ingress rule allows SSH from the public internet
deny[msg] {
  ing := open_sg.ingress[_]
  ing.cidr_blocks[_] == "0.0.0.0/0"
  ing.from_port == 22
  msg := "Open SSH access (port 22) to the internet is not allowed."
}

# Deny if any ingress rule allows RDP from the public internet
deny[msg] {
  ing := open_sg.ingress[_]
  ing.cidr_blocks[_] == "0.0.0.0/0"
  ing.from_port == 3389
  msg := "Open RDP access (port 3389) to the internet is not allowed."
}

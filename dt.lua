das_protocol = Proto("das",  "DAS Protocol")

message_start  = ProtoField.uint16("das.start",   "START",   base.HEX)
command        = ProtoField.uint8 ("das.cmd",     "CMD",     base.HEX)
ope            = ProtoField.uint8 ("das.ope",     "OPE",     base.HEX)
dm_id          = ProtoField.uint8 ("das.dm_id",   "DM ID",   base.HEX)
message_length = ProtoField.uint8 ("das.size",    "SIZE",    base.DEC)
message        = ProtoField.none  ("das.message", "MESSAGE", base.HEX)
crc32          = ProtoField.uint32("das.crc32",   "CRC32",   base.HEX)
message_end    = ProtoField.uint16("das.end",     "END",     base.HEX)

das_protocol.fields = { message_start, command, ope, dm_id, message_length, message, crc32, message_end }

function das_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = das_protocol.name

  local subtree = tree:add(das_protocol, buffer(), "DAS Protocol V1.0")

  subtree:add_le(message_start,  buffer(0,2))
  subtree:add_le(command,        buffer(2,1))
  subtree:add_le(ope,            buffer(3,1))
  subtree:add_le(dm_id,          buffer(4,1))
  subtree:add_le(message_length, buffer(5,1))

  -- protocol`s body
  subtree:add_le(message,        buffer(6,length - 12))

  subtree:add_le(crc32,          buffer(length - 6,4))
  subtree:add_le(message_end,    buffer(length - 2,2))

end

local tcp_port = DissectorTable.get("udp.port")
tcp_port:add(3000, das_protocol)
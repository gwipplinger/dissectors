local my_info = 
{
    version = "1.0.0",
    description = "Dissector to parse the OcMux protobuf protocol.",
    repository = "https://github.com/Railway-CCS/dissectors"
}

set_plugin_info(my_info)

local p_ocmux = Proto("ocmux", "OcMux Protocol")

local ocmux_packet_length     = ProtoField.uint16("ocmux.packet_length", "Packet Length")
local ocmux_protocol_type     = ProtoField.uint8("sci.type", "Protocol Type", base.HEX, {
    [0xe0] = "Max to OcMux",
    [0xe1] = "OcMux to Max"
})


p_ocmux.fields = {
        ocmux_packet_length,
        ocmux_protocol_type
    }

function p_ocmux.dissector(buf, pktinfo, root)

    local pktlen = buf:reported_length_remaining()
    local sci = nil

    local proto = buf:range(2, 2):le_uint()
    if ((proto == 0xe0) or (proto == 0xe1)) then 
        sci = root:add(p_ocmux, buf(), "OcMux")
        pktinfo.cols.protocol:set("OcMux")
    else
        return
    end

    sci:add_le(ocmux_packet_length, buf(0, 2))
    sci:add_le(ocmux_protocol_type, buf(2, 2))

    if (proto == 0xe0) then 
        pktinfo.private["pb_msg_type"] = "message,gts.maxd.aps.ocmux.proto.MaxToOcMux"
        Dissector.get("protobuf"):call(buf:range(4, pktlen - 4):tvb(), pktinfo, sci)
    elseif (proto == 0xe1) then 
        pktinfo.private["pb_msg_type"] = "message,gts.maxd.aps.ocmux.proto.OcMuxToMax"
        Dissector.get("protobuf"):call(buf:range(4, pktlen - 4):tvb(), pktinfo, sci)
    end
end


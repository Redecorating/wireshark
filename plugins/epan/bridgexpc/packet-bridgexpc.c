/* packet-bridgexpc.c
 * Routines for Apple Bridge XPC dissection
 * Copyright 2024, Orlando Chamberlain <orlandoch.dev@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Bridge XPC is used by some services on the T2 Coprocessor of
 * some Apple Mac computers, and this is how macOS communicates
 * with those services.
 *
 * https://github.com/MCMrARM/libbridgexpc/
 */

#include "config.h"
/* Define the name for the logging domain (try to avoid collisions with existing domains) */
#define WS_LOG_DOMAIN "BRIDGE_XPC"

/* Global header providing a minimum base set of required macros and APIs */
#include <wireshark.h>


#include <epan/packet.h>   /* Required dissection API header */

/* Some protocols may need code from other dissectors, as here for
 * ssl_dissector_add()
 */


/* Prototypes */
void proto_register_bridgexpc(void);

/* Initialize the protocol and registered fields */
static int proto_bridgexpc;

static int hf_bridgexpc_magic;
static int hf_bridgexpc_version;
static int hf_bridgexpc_type;
static int hf_bridgexpc_length;
static int hf_bridgexpc_bplist;


static dissector_handle_t bridgexpc_handle;

#define BRIDGE_XPC_TCP_PORT 49198 //TODO: use a range of ports, this port changes each boot

/* Initialize the subtree pointers */
static int ett_bridgexpc;

#define BRIDGE_XPC_MIN_LENGTH 16
#define BRIDGE_XPC_MAGIC 0xB892
#define BRIDGE_XPC_VERSION 1

static const value_string bridgexpcTypeNames[] = {
    {1, "BRIDGE_XPC_TYPE_HELLO" },
    {2, "BRIDGE_XPC_TYPE_DATA" },
};


/* Code to actually dissect the packets */
static int
dissect_bridgexpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *bridgexpc_tree;
    /* Other misc. local variables. */
    unsigned offset = 0;


    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < BRIDGE_XPC_MIN_LENGTH)
        return 0;

    //TODO: also warn on version != 1
    uint16_t magic = tvb_get_guint16(tvb, 0, ENC_LITTLE_ENDIAN);

    if (magic != BRIDGE_XPC_MAGIC)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BRIDGE_XPC");


    col_clear(pinfo->cinfo,COL_INFO);
    ti = proto_tree_add_item(tree, proto_bridgexpc, tvb, 0, -1, ENC_NA);

    bridgexpc_tree = proto_item_add_subtree(ti, ett_bridgexpc);

    /* Add an item to the subtree, see section 1.5 of README.dissector for more
     * information. */
    proto_tree_add_item(bridgexpc_tree, hf_bridgexpc_magic, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(bridgexpc_tree, hf_bridgexpc_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(bridgexpc_tree, hf_bridgexpc_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    uint32_t msgType = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(bridgexpc_tree, hf_bridgexpc_length, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    uint64_t length = tvb_get_guint64(tvb, offset, ENC_LITTLE_ENDIAN);
    offset += 8;

    tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, offset);

    if (msgType == 1) {
        //HELLO, disect json

       dissector_handle_t json_handle = find_dissector_add_dependency("json", proto_bridgexpc);
       call_dissector(json_handle, next_tvb, pinfo, bridgexpc_tree);
       offset += length;

    } else if (msgType == 2) {
        //DATA, disect a binary plist
        // I don't want to think too much, lets just pretend this is transformed data
        // and use plistutil to convert to json

        dissector_handle_t bplist_handle = find_dissector_add_dependency("bplist", proto_bridgexpc);
        call_dissector(bplist_handle, next_tvb, pinfo, bridgexpc_tree);
        //proto_tree_add_item(bridgexpc_tree, hf_bridgexpc_bplist, tvb, offset, length, ENC_LITTLE_ENDIAN);
        offset += length;

    }


    return tvb_captured_length(tvb);
}

void
proto_register_bridgexpc(void)
{

    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        { &hf_bridgexpc_magic,
            { "Bridge XPC Magic", "bridgexpc.magic",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_bridgexpc_version,
            { "Bridge XPC Version", "bridgexpc.version",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_bridgexpc_type,
            { "Bridge XPC Type", "bridgexpc.type",
                FT_UINT32, BASE_DEC,
                VALS(bridgexpcTypeNames), 0x0,
                NULL, HFILL }
        },
        { &hf_bridgexpc_length,
            { "Bridge XPC Length", "bridgexpc.length",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_bridgexpc_bplist,
            { "Bridge XPC Binary Property List", "bridgexpc.bplist",
                FT_BYTES, 0,
                NULL, 0x0,
                NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_bridgexpc
    };

    /* Register the protocol name and description */
    proto_bridgexpc = proto_register_protocol(
            "Bridge XPC",
            "BRIDGE XPC",
            "bridgexpc"
            );

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_bridgexpc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Use register_dissector() here so that the dissector can be
     * found by name by other protocols, by Lua, by Export PDU,
     * by custom User DLT dissection, etc. Some protocols may require
     * multiple uniquely named dissectors that behave differently
     * depending on the caller, e.g. over TCP directly vs over TLS.
     */
    bridgexpc_handle = register_dissector("bridgexpc", dissect_bridgexpc,
            proto_bridgexpc);

}

void proto_reg_handoff_bridgexpc(void) {

    bridgexpc_handle = create_dissector_handle(dissect_bridgexpc, proto_bridgexpc);
    dissector_add_uint("tcp.port", BRIDGE_XPC_TCP_PORT, bridgexpc_handle);
}


/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

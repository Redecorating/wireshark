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
#include <plist.h>

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

static int hf_bkit_msg_type;
static int hf_bkit_is_reply;
static int hf_bkit_msg_id;
static int hf_bkit_data;


static dissector_handle_t bridgexpc_handle;

#define BRIDGE_XPC_TCP_PORTS "49000-49500"

/* Initialize the subtree pointers */
static int ett_bridgexpc;

#define BRIDGE_XPC_MIN_LENGTH 16
#define BRIDGE_XPC_MAGIC 0xB892
#define BRIDGE_XPC_VERSION 1

static const value_string bridgexpcTypeNames[] = {
    {1, "BRIDGE_XPC_TYPE_HELLO" },
    {2, "BRIDGE_XPC_TYPE_DATA" },
};

#include <stdio.h>
int bplist_to_xml(const char *bplistData, unsigned bplistLength, char **xml_dest, uint32_t *xml_len) {
    plist_t plist;
    plist_err_t ret = plist_from_bin(bplistData, bplistLength, &plist);
    if (ret != PLIST_ERR_SUCCESS) {
        printf("failed to make plist (%d)\n",ret );
        return ret;
    }

    ret = plist_to_xml(plist, xml_dest, xml_len);
    if (ret) {
        printf("failed to make xml (%d)\n", ret);
    }

    plist_free(plist);
    return ret;
}

#include <epan/dissectors/packet-tcp.h>

static int
dissect_bridgexpc_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_);

static unsigned
get_bridgexpc_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_) {
    return tvb_get_guint64(tvb, offset+8, ENC_LITTLE_ENDIAN) + BRIDGE_XPC_MIN_LENGTH;
}

static int
dissect_bridgexpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_) {
    tcp_dissect_pdus(tvb, pinfo, tree, true, BRIDGE_XPC_MIN_LENGTH,
            get_bridgexpc_message_len, dissect_bridgexpc_message, data);
    return tvb_captured_length(tvb);
}

/* Code to actually dissect the packets */
static int
dissect_bridgexpc_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *bridgexpc_tree;
    /* Other misc. local variables. */
    unsigned offset = 0;
    if (tvb_reported_length(tvb) < BRIDGE_XPC_MIN_LENGTH)
        return 0;

    uint16_t magic = tvb_get_guint16(tvb, 0, ENC_LITTLE_ENDIAN);

    if (magic != BRIDGE_XPC_MAGIC)
        return 0;
    uint16_t version = tvb_get_guint16(tvb, 2, ENC_LITTLE_ENDIAN);
    if (version != 1)
        return 0;


    uint64_t length = tvb_get_guint64(tvb, 8, ENC_LITTLE_ENDIAN);



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
    offset += 8;

    tvbuff_t *next_tvb;

    dissector_handle_t json_handle = find_dissector_add_dependency("json", proto_bridgexpc);
    dissector_handle_t xml_handle = find_dissector_add_dependency("xml", proto_bridgexpc);
    dissector_handle_t bkit_handle = find_dissector_add_dependency("bkit", proto_bridgexpc);
    if (msgType == 1) {
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        //HELLO, disect json
       call_dissector(json_handle, next_tvb, pinfo, bridgexpc_tree);
       offset += length;
       col_add_fstr(pinfo->cinfo, COL_INFO, "Hello from");
        //proto_tree_children_foreach(bridgexpc_tree, proto_tree_print_node, data);

    } else if (msgType == 2) {
        tvbuff_t *plist_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector(bkit_handle, plist_tvb, pinfo, bridgexpc_tree);
        //DATA, disect a binary plist
        // I don't want to think too much, lets just pretend this is transformed data
        // and use plistutil to convert to xml
        char *xml_dest=0;
        uint32_t xml_len=0;
        bplist_to_xml(tvb_get_ptr(tvb,offset, length), length, &xml_dest, &xml_len);
        if (xml_dest) {
            // make sure this is malloced by wireshark func
            unsigned char *decompressed_buffer = (unsigned char*)wmem_alloc(pinfo->pool, xml_len);
            memcpy(decompressed_buffer, xml_dest, xml_len);
            plist_mem_free(xml_dest);
            next_tvb = tvb_new_child_real_data(tvb, decompressed_buffer, xml_len, xml_len);
            add_new_data_source(pinfo, next_tvb, "Decoded BPlist");
            call_dissector(xml_handle, next_tvb, pinfo, bridgexpc_tree);
            offset += length;
        }

    }
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BRIDGE_XPC");


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
        { &hf_bkit_msg_type,
            { "Biometric Kit Message Type", "bkit.msg_type",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_bkit_is_reply,
            { "Biometric Kit Is Reply", "bkit.is_reply",
                FT_BOOLEAN, 0,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_bkit_msg_id,
            { "Biometric Kit Message ID", "bkit.msg_id",
                FT_GUID, 0,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_bkit_data,
            { "Biometric Kit Message Data", "bkit.data",
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
    dissector_add_uint_range_with_preference("tcp.port", BRIDGE_XPC_TCP_PORTS, bridgexpc_handle);
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

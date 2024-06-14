/* packet-rxpc.c
 * Routines for Apple Remote XPC dissection
 * Copyright 2024, Orlando Chamberlain <orlandoch.dev@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: LICENSE
 */

/*
 * Remote XPC is used by some services on the T2 Coprocessor of
 * some Apple Mac computers, and this is how macOS communicates
 * with those services.
 *
 * https://duo.com/labs/research/apple-t2-xpc
 * https://github.com/MCMrARM/libxpc/
 */

#include "config.h"
/* Define the name for the logging domain (try to avoid collisions with existing domains) */
#define WS_LOG_DOMAIN "RXPC"

/* Global header providing a minimum base set of required macros and APIs */
#include <wireshark.h>


#include <epan/packet.h>   /* Required dissection API header */

/* Some protocols may need code from other dissectors, as here for
 * ssl_dissector_add()
 */


/* Prototypes */
void proto_register_rxpc(void);

/* Initialize the protocol and registered fields */
static int proto_rxpc;

static int hf_rxpc_magic;
static int hf_rxpc_version;
static int hf_rxpc_type;
static int hf_rxpc_flags;
static int hf_rxpc_length;
static int hf_rxpc_msg_id;

//static expert_field ei_RXPC_EXPERTABBREV;

static dissector_handle_t rxpc_handle;

/* Global sample port preference - real port preferences should generally
 * default to "" (for a range) or 0 (for a single uint) unless there is an
 * IANA-registered (or equivalent) port for your protocol. */
#define RXPC_TCP_PORT 59602 //may also use other ports

/* Initialize the subtree pointers */
static int ett_rxpc;

#define RXPC_MIN_LENGTH 24
#define RXPC_MAGIC 0x29B00B92

static const value_string rxpcTypeNames[] = {
    {0, "RXPC_TYPE_HELLO" },
    {1, "RXPC_TYPE_DATA" },
};


/* Code to actually dissect the packets */
static int
dissect_rxpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *rxpc_tree;
    /* Other misc. local variables. */
    unsigned offset = 0;

    /*** HEURISTICS ***/

    /* First, if at all possible, do some heuristics to check if the packet
     * cannot possibly belong to your protocol.  This is especially important
     * for protocols directly on top of TCP or UDP where port collisions are
     * common place (e.g., even though your protocol uses a well known port,
     * someone else may set up, for example, a web server on that port which,
     * if someone analyzed that web server's traffic in Wireshark, would result
     * in Wireshark handing an HTTP packet to your dissector).
     *
     * For example:
     */

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < RXPC_MIN_LENGTH)
        return 0;

    /* Fetch some values from the packet header using tvb_get_*(). If these
     * values are not valid/possible in your protocol then return 0 to give
     * some other dissector a chance to dissect it. */
    uint64_t magic = tvb_get_guint32(tvb, 9, ENC_LITTLE_ENDIAN);

    if (magic != RXPC_MAGIC)
        return 0;

    /*** COLUMN DATA ***/

    /* There are two normal columns to fill in: the 'Protocol' column which
     * is narrow and generally just contains the constant string 'RXPC',
     * and the 'Info' column which can be much wider and contain misc. summary
     * information (for example, the port number for TCP packets).
     *
     * If you are setting the column to a constant string, use "col_set_str()",
     * as it's more efficient than the other "col_set_XXX()" calls.
     *
     * If
     * - you may be appending to the column later OR
     * - you have constructed the string locally OR
     * - the string was returned from a call to val_to_str()
     * then use "col_add_str()" instead, as that takes a copy of the string.
     *
     * The function "col_add_fstr()" can be used instead of "col_add_str()"; it
     * takes "printf()"-like arguments. Don't use "col_add_fstr()" with a format
     * string of "%s" - just use "col_add_str()" or "col_set_str()", as it's
     * more efficient than "col_add_fstr()".
     *
     * For full details see section 1.4 of README.dissector.
     */

    /* Set the Protocol column to the constant string of RXPC */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RXPC");

#if 0
    /* If you will be fetching any data from the packet before filling in
     * the Info column, clear that column first in case the calls to fetch
     * data from the packet throw an exception so that the Info column doesn't
     * contain data left over from the previous dissector: */
    col_clear(pinfo->cinfo, COL_INFO);
#endif

    /*** PROTOCOL TREE ***/

    /* Now we will create a sub-tree for our protocol and start adding fields
     * to display under that sub-tree. Most of the time the only functions you
     * will need are proto_tree_add_item() and proto_item_add_subtree().
     *
     * NOTE: The offset and length values in the call to proto_tree_add_item()
     * define what data bytes to highlight in the hex display window when the
     * line in the protocol tree display corresponding to that item is selected.
     *
     * Supplying a length of -1 tells Wireshark to highlight all data from the
     * offset to the end of the packet.
     */

    col_clear(pinfo->cinfo,COL_INFO);
    ti = proto_tree_add_item(tree, proto_rxpc, tvb, 9, -1, ENC_NA);

    rxpc_tree = proto_item_add_subtree(ti, ett_rxpc);

    /* Add an item to the subtree, see section 1.5 of README.dissector for more
     * information. */
    offset += 9; //Why tho...
    proto_tree_add_item(rxpc_tree, hf_rxpc_magic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(rxpc_tree, hf_rxpc_version, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(rxpc_tree, hf_rxpc_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(rxpc_tree, hf_rxpc_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(rxpc_tree, hf_rxpc_length, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(rxpc_tree, hf_rxpc_msg_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    /* If this protocol has a sub-dissector call it here, see section 1.8 of
     * README.dissector for more information. */
    tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, offset);
    dissector_handle_t xpc_handle = find_dissector_add_dependency("xpc", proto_rxpc);
    call_dissector(xpc_handle, next_tvb, pinfo, rxpc_tree);

    /* Return the amount of data this dissector was able to dissect (which may
     * or may not be the total captured packet as we return here). */
    return tvb_captured_length(tvb);
}


#define RXPC_HEARTBEAT_FLAG            1<<0
#define RXPC_HEARTBEAT_REPLY_FLAG      1<<1
#define RXPC_NEW_FILE_TX_STREAM_FLAG   1<<4
#define RXPC_TX_STREAM_REPLY_FLAG      1<<5
#define RXPC_SYSDIAGNOSE_INIT_FLAG     1<<6
#define RXPC_REPLY_CHANNEL_FLAG        0x40 //im too tired to do log2


/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_rxpc(void)
{

    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        { &hf_rxpc_magic,
            { "RXPC Magic", "rxpc.magic",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_rxpc_version,
            { "RXPC Version", "rxpc.version",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_rxpc_type,
            { "RXPC Type", "rxpc.type",
                FT_UINT8, BASE_DEC,
                VALS(rxpcTypeNames), 0x0,
                NULL, HFILL }
        },
        { &hf_rxpc_flags,
            { "RXPC Flags", "rxpc.flags",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_rxpc_length,
            { "RXPC Length", "rxpc.length",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_rxpc_msg_id,
            { "RXPC Message ID", "rxpc.msg_id",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_rxpc
    };

    /* Register the protocol name and description */
    proto_rxpc = proto_register_protocol(
            "Remote XPC",
            "RXPC",
            "rxpc"
            );

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_rxpc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Use register_dissector() here so that the dissector can be
     * found by name by other protocols, by Lua, by Export PDU,
     * by custom User DLT dissection, etc. Some protocols may require
     * multiple uniquely named dissectors that behave differently
     * depending on the caller, e.g. over TCP directly vs over TLS.
     */
    rxpc_handle = register_dissector("rxpc", dissect_rxpc,
            proto_rxpc);

}

void proto_reg_handoff_rxpc(void) {

    rxpc_handle = create_dissector_handle(dissect_rxpc, proto_rxpc);
    dissector_add_uint("tcp.port", RXPC_TCP_PORT, rxpc_handle);
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

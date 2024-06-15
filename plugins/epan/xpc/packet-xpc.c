/* packet-xpc.c
 * Routines for Apple XPC dissection
 * Copyright 2024, Orlando Chamberlain <orlandoch.dev@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * A serialised data format used by apple for cross process communication
 * This is encapsulated in Remote XPC sometimes
 *
 * https://github.com/MCMrARM/libxpc
 * https://developer.apple.com/documentation/xpc/
 */

#include "config.h"
/* Define the name for the logging domain (try to avoid collisions with existing domains) */
#define WS_LOG_DOMAIN "xpc"

/* Global header providing a minimum base set of required macros and APIs */
#include <wireshark.h>

#include <epan/packet.h>   /* Required dissection API header */

/* IF AND ONLY IF your protocol dissector exposes code to other dissectors
 * (which most dissectors don't need to do) then the 'public' prototypes and
 * data structures can go in the header file packet-xpc.h. If not, then
 * a header file is not needed at all and this #include statement can be
 * removed. */


/* Prototypes */
void proto_reg_handoff_xpc(void);
void proto_register_xpc(void);

/* Initialize the protocol and registered fields */
static int proto_xpc;
static int hf_xpc_magic;
static int hf_xpc_version;
static int hf_xpc_type;

static dissector_handle_t xpc_handle;

/* Initialize the subtree pointers */
static int ett_xpc;

/* A sample #define of the minimum length (in bytes) of the protocol data.
 * If data is received with fewer than this many bytes it is rejected by
 * the current dissector. */
#define XPC_MIN_LENGTH 16
#define XPC_MAGIC 0x42133742
#define XPC_VERSION 5

/* Code to actually dissect the packets */
static int
dissect_xpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *xpc_tree;
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
    if (tvb_reported_length(tvb) < XPC_MIN_LENGTH)
        return 0;

    /* Fetch some values from the packet header using tvb_get_*(). If these
     * values are not valid/possible in your protocol then return 0 to give
     * some other dissector a chance to dissect it. */
    if (tvb_get_guint32(tvb,0,ENC_LITTLE_ENDIAN) != XPC_MAGIC)
        return 0;

    /*** COLUMN DATA ***/

    /* There are two normal columns to fill in: the 'Protocol' column which
     * is narrow and generally just contains the constant string 'xpc',
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

    /* Set the Protocol column to the constant string of xpc */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "XPC");

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

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_xpc, tvb, 0, -1, ENC_NA);

    xpc_tree = proto_item_add_subtree(ti, ett_xpc);

    proto_tree_add_item(xpc_tree, hf_xpc_magic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(xpc_tree, hf_xpc_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(xpc_tree, hf_xpc_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;


    /* If this protocol has a sub-dissector call it here, see section 1.8 of
     * README.dissector for more information. */

    /* Return the amount of data this dissector was able to dissect (which may
     * or may not be the total captured packet as we return here). */
    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_xpc(void)
{
    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        { &hf_xpc_magic,
          { "XPC Magic", "xpc.magic",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xpc_version,
          { "XPC Version", "xpc.version",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xpc_type,
          { "XPC Object Type", "xpc.type",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_xpc
    };

    /* Register the protocol name and description */
    proto_xpc = proto_register_protocol("Apple XPC", "XPC", "xpc");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_xpc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));


    /* Use register_dissector() here so that the dissector can be
     * found by name by other protocols, by Lua, by Export PDU,
     * by custom User DLT dissection, etc. Some protocols may require
     * multiple uniquely named dissectors that behave differently
     * depending on the caller, e.g. over TCP directly vs over TLS.
     */
    xpc_handle = register_dissector("xpc", dissect_xpc,
            proto_xpc);

}

/* If this dissector uses sub-dissector registration add a registration routine.
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * If this function is registered as a prefs callback (see
 * prefs_register_protocol above) this function is also called by Wireshark's
 * preferences manager whenever "Apply" or "OK" are pressed. In that case, it
 * should accommodate being called more than once by use of the static
 * 'initialized' variable included below.
 *
 * This form of the reg_handoff function is used if you perform registration
 * functions which are dependent upon prefs. See below this function for a
 * simpler form which can be used if there are no prefs-dependent registration
 * functions.
 */
void
proto_reg_handoff_xpc(void)
{
    xpc_handle = create_dissector_handle(dissect_xpc, proto_xpc);
}

#if 0

/* Simpler form of proto_reg_handoff_xpc which can be used if there are
 * no prefs-dependent registration function calls. */
void
proto_reg_handoff_xpc(void)
{
    dissector_add_uint_range_with_preference("tcp.port", xpc_TCP_PORTS, xpc_handle);
}
#endif

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

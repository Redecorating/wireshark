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

/* Prototypes */
void proto_reg_handoff_xpc(void);
void proto_register_xpc(void);

/* Initialize the protocol and registered fields */
static int proto_xpc;
static int hf_xpc_magic;
static int hf_xpc_version;
static int hf_xpc_type;
static int hf_xpc_obj_bool;
static int hf_xpc_obj_int64;
static int hf_xpc_obj_uint64;
static int hf_xpc_obj_double;
static int hf_xpc_obj_string;
static int hf_xpc_obj_size; //padded to multiple of 4 bytes
static int hf_xpc_obj_entry_count;
static int hf_xpc_obj_dict_key;

static dissector_handle_t xpc_handle;

/* Initialize the subtree pointers */
static int ett_xpc;

#define XPC_MIN_LENGTH 12
#define XPC_MAGIC 0x42133742
#define XPC_VERSION 5

#define XPC_TYPE(x) x<<12

enum xpc_value_type {
    XPC_NULL = XPC_TYPE(1),
    XPC_BOOL = XPC_TYPE(2),
    XPC_INT64 = XPC_TYPE(3),
    XPC_UINT64 = XPC_TYPE(4),
    XPC_DOUBLE = XPC_TYPE(5),
    XPC_POINTER = XPC_TYPE(6),
    XPC_DATE = XPC_TYPE(7),
    XPC_DATA = XPC_TYPE(8),
    XPC_STRING = XPC_TYPE(9),
    XPC_UUID = XPC_TYPE(10),
    XPC_FD = XPC_TYPE(11),
    XPC_SHMEM = XPC_TYPE(12),
    XPC_MACH_SEND = XPC_TYPE(13),
    XPC_ARRAY = XPC_TYPE(14),
    XPC_DICTIONARY = XPC_TYPE(15),
    XPC_ERROR = XPC_TYPE(16),
    XPC_CONNECTION = XPC_TYPE(17),
    XPC_ENDPOINT = XPC_TYPE(18),
    XPC_SERIALIZER = XPC_TYPE(19),
    XPC_PIPE = XPC_TYPE(20),
    XPC_MACH_RECV = XPC_TYPE(21),
    XPC_BUNDLE = XPC_TYPE(22),
    XPC_SERVICE = XPC_TYPE(23),
    XPC_SERVICE_INSTANCE = XPC_TYPE(24),
    XPC_ACTIVITY = XPC_TYPE(25),
    XPC_FILE_TRANSFER = XPC_TYPE(26),
};

static const value_string xpcTypeNames[] = {
    { XPC_NULL, "XPC_NULL" },
    { XPC_BOOL, "XPC_BOOL" },
    { XPC_INT64, "XPC_INT64" },
    { XPC_UINT64, "XPC_UINT64" },
    { XPC_DOUBLE, "XPC_DOUBLE" },
    { XPC_POINTER, "XPC_POINTER" },
    { XPC_DATE, "XPC_DATE" },
    { XPC_DATA, "XPC_DATA" },
    { XPC_STRING, "XPC_STRING" },
    { XPC_UUID, "XPC_UUID" },
    { XPC_FD, "XPC_FD" },
    { XPC_SHMEM, "XPC_SHMEM" },
    { XPC_MACH_SEND, "XPC_MACH_SEND" },
    { XPC_ARRAY, "XPC_ARRAY" },
    { XPC_DICTIONARY, "XPC_DICTIONARY" },
    { XPC_ERROR, "XPC_ERROR" },
    { XPC_CONNECTION, "XPC_CONNECTION" },
    { XPC_ENDPOINT, "XPC_ENDPOINT" },
    { XPC_SERIALIZER, "XPC_SERIALIZER" },
    { XPC_PIPE, "XPC_PIPE" },
    { XPC_MACH_RECV, "XPC_MACH_RECV" },
    { XPC_BUNDLE, "XPC_BUNDLE" },
    { XPC_SERVICE, "XPC_SERVICE" },
    { XPC_SERVICE_INSTANCE, "XPC_SERVICE_INSTANCE" },
    { XPC_ACTIVITY, "XPC_ACTIVITY" },
    { XPC_FILE_TRANSFER, "XPC_FILE_TRANSFER" }
};

static int dissect_xpc_object(tvbuff_t *tvb, unsigned offset, proto_tree *tree);

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


    if (tvb_reported_length(tvb) < XPC_MIN_LENGTH)
        return 0;

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
    offset += dissect_xpc_object(tvb, offset, xpc_tree);


    /* If this protocol has a sub-dissector call it here, see section 1.8 of
     * README.dissector for more information. */

    /* Return the amount of data this dissector was able to dissect (which may
     * or may not be the total captured packet as we return here). */
    return tvb_captured_length(tvb);
}

static int
dissect_xpc_object(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    uint32_t type = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
    //printf("enter %s, offset=%u, type=0x%x\n",__func__, offset,type);
    proto_tree_add_item(tree, hf_xpc_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    switch (type) {
        case XPC_BOOL:
            proto_tree_add_item(tree, hf_xpc_obj_bool, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+= 4;
            break;
        case XPC_INT64:
            proto_tree_add_item(tree, hf_xpc_obj_int64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset+= 8;
            break;
        case XPC_UINT64:
            proto_tree_add_item(tree, hf_xpc_obj_uint64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset+= 8;
            break;
        case XPC_DOUBLE:
            proto_tree_add_item(tree, hf_xpc_obj_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset+= 8;
            break;
        case XPC_DATA:
            break;
        case XPC_STRING:
            uint32_t string_length = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
            // round up to 32 bit words
            if (string_length % 4) {
                string_length += (4-(string_length%4));
            }
            proto_tree_add_item(tree, hf_xpc_obj_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_xpc_obj_string, tvb, offset, string_length, ENC_NA);
            offset += string_length;
            break;
        case XPC_UUID:
            break;
        case XPC_ARRAY:
            break;
        case XPC_DICTIONARY:
            uint32_t dict_length = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
            // round up to 32 bit words
            if (dict_length % 4) {
                dict_length += (4-(dict_length%4));
            }
            uint32_t dict_end = dict_length + offset;
            proto_tree_add_item(tree, hf_xpc_obj_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            uint32_t dict_entry_count = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_xpc_obj_entry_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            uint8_t c;
            int strlength = 0;
            for (unsigned i = 0; i < dict_entry_count; i++) {
                proto_tree *dict_entry_tree = proto_item_add_subtree(tree, ett_xpc);
                
                // TODO find where wireshark implements strlen
                strlength = 0;
                do {
                    c = tvb_get_guint8(tvb, offset+strlength);
                    strlength++;
                } while (c);
                if (strlength % 4) {
                    strlength += (4-(strlength%4));
                }

                proto_tree_add_item(dict_entry_tree, hf_xpc_obj_dict_key, tvb, offset, strlength, ENC_NA);
                offset += strlength;
                offset = dissect_xpc_object(tvb, offset, dict_entry_tree);
            }
            offset = dict_end;

            break;
        case XPC_NULL:
        case XPC_POINTER:
        case XPC_DATE:
        case XPC_FD:
        case XPC_SHMEM:
        case XPC_MACH_SEND:
        case XPC_ERROR:
        case XPC_CONNECTION:
        case XPC_ENDPOINT:
        case XPC_SERIALIZER:
        case XPC_PIPE:
        case XPC_MACH_RECV:
        case XPC_BUNDLE:
        case XPC_SERVICE:
        case XPC_SERVICE_INSTANCE:
        case XPC_ACTIVITY:
        case XPC_FILE_TRANSFER:
            break;
    }

    return offset;
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
            VALS(xpcTypeNames), 0x0,
            NULL, HFILL }
        },
        { &hf_xpc_obj_size,
          { "XPC Object Contents Size", "xpc.obj.size",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xpc_obj_entry_count,
          { "XPC Object Entry Count", "xpc.obj.count",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xpc_obj_dict_key,
          { "XPC Dictionary Key", "xpc.obj.count",
            FT_STRINGZ, 0,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xpc_obj_bool,
          { "XPC Bool", "xpc.obj.bool",
            FT_BOOLEAN, 0,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xpc_obj_int64,
          { "XPC int64", "xpc.obj.int64",
            FT_INT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xpc_obj_uint64,
          { "XPC uint64", "xpc.obj.uint64",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xpc_obj_double,
          { "XPC Double", "xpc.obj.double",
            FT_DOUBLE, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xpc_obj_string,
          { "XPC String", "xpc.obj.string",
            FT_STRINGZ, 0,
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


    xpc_handle = register_dissector("xpc", dissect_xpc,
            proto_xpc);

}

void
proto_reg_handoff_xpc(void)
{
    xpc_handle = create_dissector_handle(dissect_xpc, proto_xpc);
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

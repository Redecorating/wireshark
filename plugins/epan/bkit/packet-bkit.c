/* packet-bkit.c
 * Routines for Apple Biometric Kit dissection
 * Copyright 2024, Orlando Chamberlain <orlandoch.dev@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Biometric Kit is used for TouchID on T2 Macs
 */

#include "config.h"
/* Define the name for the logging domain (try to avoid collisions with existing domains) */
#define WS_LOG_DOMAIN "BKIT"

#include <plist.h>

/* Global header providing a minimum base set of required macros and APIs */
#include <wireshark.h>


#include <epan/packet.h>   /* Required dissection API header */
#include <epan/conversation.h>

/* Some protocols may need code from other dissectors, as here for
 * ssl_dissector_add()
 */

#define BK_NULL "d4161201-daf5-4bbd-ae4f-9bf319fabbe0"

/* Prototypes */
void proto_register_bkit(void);

/* Initialize the protocol and registered fields */
static int proto_bkit;

static int hf_bkit_env_type;
static int hf_bkit_env_is_reply;
static int hf_bkit_env_msg_id;
static int hf_bkit_cmd_id;

static int hf_bkit_krn_data;
static int hf_bkit_krn_magic;
static int hf_bkit_krn_cmd_id;
static int hf_bkit_krn_version;
static int hf_bkit_krn_in_val;
// and then the krn cmd may have more stuff after this.

//static expert_field ei_BKIT_EXPERTABBREV;

static dissector_handle_t bkit_handle;

/* Initialize the subtree pointers */
static int ett_bkit;
static int ett_bkit_kern;

static const value_string bkitEnvTypeNames[] = {
    {0L, "PING" },
    {1L, "MESSAGE" },
};

static const value_string bKitCommandIds[] = {
    {0, "GetBridgeVersion" },
    {1, "GetServiceOpened" },
    {2, "GetSystemBootTime" },
    {3, "PerformCommand" },
    {4, "SetIORegistryProperty" },
    {5, "GetCalibrationDataFromEEPROM" },
    {6, "MachContinousTime" },
    {7, "GetMachTimebaseInfo" },
    {8, "GetOSVersion" },
    {10, "SetBridgeClientVersion" },
    {11, "GetCalibrationDataFromFDR" },
    { 0, NULL}
};

static const value_string bKitKernelCmdIds[] = {
    {1, "GetCommProtocolVersion" },
    {2, "ResetSensor" },
    {3, "StartEnroll" },
    {4, "StartMatch" },
    {5, "SetTemplateListSU" },
    {6, "GetTemplateListSUSize" },
    {7, "GetTemplateListSU" },
    {8, "GetAlignmentData" },
    {9, "GetCaptureBuffer" },
    {0xA, "GetDebugImageData" },
    {0xB, "GetDebugImageData2" },
    {0xC, "Cancel" },
    {0xD, "RemoveIdentity" },
    {0xE, "ContinueEnroll" },
    {0xF, "GetMaxIdentityCount" },
    {0x10, "GetProvisioningState" },
    {0x11, "GetNodeTopology" },
    {0x14, "NotifyDisplayPowerChanged" },
    {0x15, "RegisterDSID" },
    {0x16, "RegisterStoreToken" },
    {0x17, "GetCountersignedStoreToken" },
    {0x1A, "GetCalibrationDataInfo" },
    {0x1B, "GetUserSerializedTemplateList" },
    {0x1C, "BumbCatacombCounter" },
    {0x1D, "GetSensorCalibrationStatus" },
    {0x1, "GetUserSerializedTemplateListSize" },
    {0x20, "SetCalibrationData" },
    {0x22, "GetModuleSerialNumber" },
    {0x23, "PullMatchPolicyInfoData" },
    {0x24, "LoadCustomPatch" },
    {0x26, "StartDetectFinger" },
    {0x27, "GetSKSLockState" },
    {0x28, "GetBiometricKitdInfo" },
    {0x29, "GetDiagnosticInfo" },
    {0x2A, "GetLoggingType" },
    {0x2B, "ExtractStatusMessageData" },
    {0x2C, "SetBioLogState" },
    {0x2D, "SetUserDSID" },
    {0x2E, "GetProtectedConfiguration" },
    {0x2F, "SetProtectedConfiguration" },
    {0x30, "GetEnabledForUnlock" },
    {0x31, "Unknown0x31" },
    {0x32, "HasIdentity" },
    {0x33, "GetTimestampCollection" },
    {0x34, "ResetAppleConnectCounter" },
    {0x35, "GetSensorInfo" },
    {0x38, "GetIdentityUUID" },
    {0x39, "DropUnlockToken" },
    {0x3A, "GetIdentityHash" },
    {0x3C, "GetCatacombState" },
    {0x3D, "GetUserSecureDataLength" },
    {0x3E, "GetUserSecureData" },
    {0x3F, "BumpUserSecureDataCounter" },
    {0x40, "SetUserSecureData" },
    {0x41, "GetFreeIdentityCount" },
    {0x42, "GetUserTemplateList" },
    {0x43, "GetSystemProtectedConfiguration" },
    {0x45, "EnableBackgroundFdet" },
    {0x46, "NotifyTouchIdButtonPressed" },
    {0x47, "GetTemplateListCRC" },
    {0x48, "RemoveUser" },
    {0x49, "ForceBioLockout" },
    {0x4A, "GetBioLockoutData" },
    {0x4B, "SetBioLockoutData" },
    {0x4C, "IsXartAvailable" },
    { 0, NULL}
};

static int hf_bkit_response_in;
static int hf_bkit_response_to;

typedef struct _bkit_transaction_t {
    uint32_t req_frame;
    uint32_t rep_frame;
} bkit_transaction_t;

typedef struct _bkit_conv_info_t {
    wmem_map_t *pdus;
    //TODO: include command type
} bkit_conv_info_t;

static int dissect_bkit_type9(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
        void *data _U_)
{
    // TYPE 9 (reply):
    // [9, 3825172480, data, time?, 2452227927]
    proto_item *ti;
    proto_tree *kern_tree;
    //unsigned offset = 0;

    //if (tvb_reported_length(tvb) < 8)
    //    return 0;

    ti = proto_tree_add_item(tree, proto_bkit, tvb, 0, -1, ENC_NA);

    kern_tree =proto_item_add_subtree(ti, ett_bkit_kern);

    if (false)
        kern_tree++;
    
    /*

    proto_tree_add_item(kern_tree, hf_bkit_krn_magic, tvb, offset,2,ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(kern_tree, hf_bkit_krn_cmd_id, tvb, offset,2,ENC_LITTLE_ENDIAN);

    uint16_t cmd_id = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s", try_val_to_str(cmd_id, bKitKernelCmdIds));

    offset += 2;
    proto_tree_add_item(kern_tree, hf_bkit_krn_version, tvb, offset,2,ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(kern_tree, hf_bkit_krn_in_val, tvb, offset,2,ENC_LITTLE_ENDIAN);
    offset += 2;
    */
    return tvb_captured_length(tvb);
}


static int dissect_bkit_kernel_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti;
    proto_tree *kern_tree;
    unsigned offset = 0;

    if (tvb_reported_length(tvb) < 8)
        return 0;
    uint16_t magic = tvb_get_guint16(tvb, 0, ENC_LITTLE_ENDIAN);
    if (magic != 0x4D42)
        return 0;


    ti = proto_tree_add_item(tree, proto_bkit, tvb, 0, -1, ENC_NA);

    kern_tree = proto_item_add_subtree(ti, ett_bkit_kern);

    proto_tree_add_item(kern_tree, hf_bkit_krn_magic, tvb, offset,2,ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(kern_tree, hf_bkit_krn_cmd_id, tvb, offset,2,ENC_LITTLE_ENDIAN);

    uint16_t cmd_id = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s", try_val_to_str(cmd_id, bKitKernelCmdIds));

    offset += 2;
    proto_tree_add_item(kern_tree, hf_bkit_krn_version, tvb, offset,2,ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(kern_tree, hf_bkit_krn_in_val, tvb, offset,2,ENC_LITTLE_ENDIAN);
    offset += 2;
                   // kCmdDataLen= (long) &bKitKernelCmdIds;
                // bKitKernelCmdIds
    return tvb_captured_length(tvb);
}


/* Code to actually dissect the packets */
static int
dissect_bkit(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *bkit_tree;

    col_clear(pinfo->cinfo,COL_INFO);
    ti = proto_tree_add_item(tree, proto_bkit, tvb, 0, -1, ENC_NA);

    bkit_tree = proto_item_add_subtree(ti, ett_bkit);

    plist_t envelope;
    plist_err_t err = plist_from_bin(tvb_get_ptr(tvb,0, -1), tvb_captured_length_remaining(tvb, 0), &envelope);
    if (err) {
        return 0;
    }
    if (plist_array_get_size(envelope) >= 4) {
        uint64_t bkit_env_type = 0;
        plist_get_uint_val(plist_array_get_item(envelope,0), &bkit_env_type);
        proto_tree_add_uint64(bkit_tree, hf_bkit_env_type, tvb, 0,0, bkit_env_type);
        uint8_t bkit_env_is_reply = 0;
        plist_get_bool_val(plist_array_get_item(envelope,1), &bkit_env_is_reply);
        proto_tree_add_boolean(bkit_tree, hf_bkit_env_is_reply, tvb, 0,0, bkit_env_is_reply);

        if (bkit_env_is_reply) {
            col_append_str(pinfo->cinfo, COL_INFO, "Reply");
        } else {
            //col_append_str(pinfo->cinfo, COL_INFO, "     ");
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s", try_val_to_str(bkit_env_type, bkitEnvTypeNames));
        }

        const char *message_id = plist_get_string_ptr(plist_array_get_item(envelope,2), 0);
        proto_tree_add_string(bkit_tree, hf_bkit_env_msg_id, tvb, 0,0, message_id);

        // REPLY MATCHING
        if (strcmp(message_id, BK_NULL)) {
            // The message ID is 16 byte GUID, this can't fit in a u32 so we will have to make do with hashing
            uint32_t seq_num = wmem_strong_hash(message_id, sizeof(BK_NULL)-1);
            conversation_t *conversation;
            bkit_conv_info_t *bkit_info;
            bkit_transaction_t *bkit_trans = NULL;
            conversation = find_or_create_conversation(pinfo);
            bkit_info = (bkit_conv_info_t *)conversation_get_proto_data(conversation, proto_bkit);
            if (!bkit_info) {
                bkit_info = wmem_new(wmem_file_scope(), bkit_conv_info_t);
                bkit_info->pdus=wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
                conversation_add_proto_data(conversation, proto_bkit, bkit_info);
            }

            bkit_trans = (bkit_transaction_t *)wmem_map_lookup(bkit_info->pdus, GUINT_TO_POINTER(seq_num));
            if (!bkit_trans) {
                //TODO: check for collisons
                bkit_trans=wmem_new(wmem_file_scope(), bkit_transaction_t);
                bkit_trans->rep_frame = 0;
                bkit_trans->req_frame = 0;
                wmem_map_insert(bkit_info->pdus, GUINT_TO_POINTER(seq_num), (void *)bkit_trans);
            }
            if (!PINFO_FD_VISITED(pinfo)) {
                if (bkit_env_is_reply) {
                    // this is the reply
                    bkit_trans->rep_frame = pinfo->num;
                } else {
                    // this is the request
                    bkit_trans->req_frame = pinfo->num;
                }
            }

            if (bkit_env_is_reply) {
                //reply
                if (bkit_trans->req_frame) {
                proto_item *it;
                it = proto_tree_add_uint(bkit_tree, hf_bkit_response_to,
                        tvb, 0, 0, bkit_trans->req_frame);
                proto_item_set_generated(it);
                }
            } else {
                // request
                if (bkit_trans->rep_frame) {
                proto_item *it;
                it = proto_tree_add_uint(bkit_tree, hf_bkit_response_in,
                        tvb, 0, 0, bkit_trans->rep_frame);
                proto_item_set_generated(it);
                }
            }
        }


        if (bkit_env_type == 1) {
            // message
            plist_t message = plist_array_get_item(envelope,3);
            uint64_t bkit_cmd_id = 0;
            plist_get_uint_val(plist_array_get_item(message,0), &bkit_cmd_id);
            // first item is cmd, uint64
            proto_tree_add_uint(bkit_tree, hf_bkit_cmd_id, tvb, 0,0, bkit_cmd_id);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s", try_val_to_str(bkit_cmd_id, bKitCommandIds));
#define BKKernelMagic 0x4d42
            // TYPE 9 (reply):
            // [9, 3825172480, data, time?, 2452227927]
            // TYPE 3:
            // [3, 0, data]
            // TYPE 0 is a reply:
            // [0, uuid/data/int] or even just [0]
            if (bkit_cmd_id == 3 || bkit_cmd_id == 9 || (bkit_cmd_id == 0 && bkit_env_is_reply )) {
                // kernel command
                // second item is 0
                // third item is data
                plist_t data_obj = plist_array_get_item(message,2);
                plist_type data_type = plist_get_node_type(data_obj);

                if (data_type == PLIST_DATA) {
                    uint64_t kCmdDataLen = 0;
                    const char *kCmdData = plist_get_data_ptr(data_obj, &kCmdDataLen);
                    unsigned char *copy = (unsigned char*)wmem_alloc(pinfo->pool, kCmdDataLen);
                    memcpy(copy, kCmdData, kCmdDataLen);
                    tvbuff_t *krn_tvb = tvb_new_child_real_data(tvb, copy, kCmdDataLen, kCmdDataLen);
                    if (bkit_cmd_id == 3) {
                        add_new_data_source(pinfo, krn_tvb, "BKit Kernel Command Data");
                        dissect_bkit_kernel_data(krn_tvb, pinfo, bkit_tree, data);
                        // fourth item is replysize
                    } else if (bkit_cmd_id == 9) {
                        add_new_data_source(pinfo, krn_tvb, "BKit Kernel Type 9 Data");
                        dissect_bkit_type9(krn_tvb, pinfo, bkit_tree, data);
                    }
                } else {
                    // lets just make it into json, im lazy
                    char * json_dest = 0;
                    uint32_t json_len = 0;
                    plist_err_t ret = plist_to_json(data_obj, &json_dest, &json_len, 0);
                    if (!ret) {
                        unsigned char *decompressed_buffer = (unsigned char*)wmem_alloc(pinfo->pool, json_len);
                        memcpy(decompressed_buffer, json_dest, json_len);
                        plist_mem_free(json_dest);
                        tvbuff_t *next_tvb = tvb_new_child_real_data(tvb, decompressed_buffer, json_len, json_len);
                        add_new_data_source(pinfo, next_tvb, "message data");

                    }

                }
            }
        } else {
            // ping
            col_add_fstr(pinfo->cinfo, COL_INFO, "Bkit Ping");
        }

    }
    //TODO: free plist
    plist_free(envelope);

    return tvb_captured_length(tvb);
}

void
proto_register_bkit(void)
{
    static hf_register_info hf[] = {
        { &hf_bkit_env_type,
            { "BKit Envolope Type", "bkit.env_type",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_bkit_env_is_reply,
            { "BKit Is Reply", "bkit.is_reply",
                FT_BOOLEAN, 0,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_bkit_env_msg_id,
            { "BKit Message ID", "bkit.msg_id",
                FT_STRINGZ, 0,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_bkit_cmd_id,
            { "BKit Command", "bkit.cmd_id",
                FT_UINT32, BASE_DEC, // this is actually uint64 but i get ("field bkit.cmd_id is a 64-bit field with a 32-bit value_string", group=1, code=6)
                VALS(bKitCommandIds), 0x0,
                NULL, HFILL }
        },
        { &hf_bkit_krn_data,
            { "BKit Kern Data", "bkit.kern_data",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_bkit_krn_magic,
            { "BKit Kern Magic", "bkit.kern_magic",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_bkit_krn_version,
            { "BKit Kern Version", "bkit.kern_version",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_bkit_krn_cmd_id,
            { "BKit Kern Command ID", "bkit.kern_cmd_id",
                FT_UINT16, BASE_DEC,
                VALS(bKitKernelCmdIds), 0x0,
                NULL, HFILL }
        },
        { &hf_bkit_krn_in_val,
            { "BKit Kern In Val", "bkit.kern_in_val",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_bkit_response_in,
            { "Response In", "bkit.response_in",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
            "The response to this BKIT request is in this frame", HFILL }
        },
        { &hf_bkit_response_to,
            { "Request In", "bkit.response_to",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
            "This is a response to the BKIT request in this frame", HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_bkit,
        &ett_bkit_kern,
    };

    /* Register the protocol name and description */
    proto_bkit = proto_register_protocol(
            "Biometric Kit",
            "BKIT",
            "bkit"
            );

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_bkit, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Use register_dissector() here so that the dissector can be
     * found by name by other protocols, by Lua, by Export PDU,
     * by custom User DLT dissection, etc. Some protocols may require
     * multiple uniquely named dissectors that behave differently
     * depending on the caller, e.g. over TCP directly vs over TLS.
     */
    bkit_handle = register_dissector("bkit", dissect_bkit,
            proto_bkit);

}

void proto_reg_handoff_bkit(void) {

    bkit_handle = create_dissector_handle(dissect_bkit, proto_bkit);
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

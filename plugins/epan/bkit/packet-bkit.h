
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
    {0, "PING" },
    {1, "MESSAGE" },
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
    {9, "TYPE9" },
    {10, "SetBridgeClientVersion" },
    {11, "GetCalibrationDataFromFDR" },
    {12, "TYPE12" },
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


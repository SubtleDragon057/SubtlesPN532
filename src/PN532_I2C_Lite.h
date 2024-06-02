#ifndef PN532_I2C_Lite_H
#define PN532_I2C_Lite_H
#include <Wire.h>

class PN532_I2C
{
public:
    PN532_I2C(TwoWire& wire = Wire, uint16_t timeout = 1000);

#pragma region Public Structs

    struct PN532_Params {
        bool useNAD = false;
        bool useDID = false;
        bool useAutoATR = true;
        bool useAutoRATS = true;
        bool enablePICCMode = false; // default is true
        bool suppressPrePostAmble = true; // default is false
        PN532_Params() {};
    };

    // Config structs for the Baudrate configs not included
    struct RFConfigData {
        enum CfgItem {
            Field = 0x01,
            Timings = 0x02,
            MaxRtyCOM = 0x04,
            MaxRetry = 0x05
        };

        byte ConfigData[3];
        uint8_t DataLength;
        CfgItem GetConfigItemType() { return cfgItemType; }

    protected:
        CfgItem cfgItemType;
    };

    struct RFField_ConfigData : public RFConfigData {

        RFField_ConfigData(bool useAutoRFCA, bool fieldOn) {
            cfgItemType = Field;
            DataLength = 1;
            ConfigData[0] = 0x00;

            ConfigData[0] ^= (useAutoRFCA << 1);
            ConfigData[0] ^= (fieldOn << 0);
        }
    };
    struct VariousTimings_ConfigData : public RFConfigData {

        VariousTimings_ConfigData(byte RESTimeout = 0x0B, byte retryTimeout = 0x0A) {
            cfgItemType = Timings;
            DataLength = 3;
            ConfigData[0] = 0x00;
            ConfigData[1] = RESTimeout;     // Formula for timing in Micro-seconds
            ConfigData[2] = retryTimeout;   // T = 100 * 2^(n-1) where n = user input
        }
    };
    struct MaxRetryCOM_ConfigData : public RFConfigData {

        MaxRetryCOM_ConfigData(byte maxRetries = 0x00) {
            cfgItemType = MaxRtyCOM;
            DataLength = 1;
            ConfigData[0] = maxRetries; // 0xFF is intinite retries
        }
    };
    struct MaxRetries_ConfigData : public RFConfigData {

        MaxRetries_ConfigData(byte maxRtyATR = 0xFF, byte maxRtyPSL = 0x01, byte maxPassiveActivation = 0xFF) {
            cfgItemType = MaxRetry;
            DataLength = 3;

            ConfigData[0] = maxRtyATR;
            ConfigData[1] = maxRtyPSL;
            ConfigData[2] = maxPassiveActivation;
        }
    };

    struct MifareClassic {
        static const uint8_t UIDLen = 4;
        uint8_t UID[UIDLen];        
        uint8_t AuthKey[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        uint8_t AuthorizedBlock = 0;
        bool Initialized = false;
    };

#pragma endregion

#pragma region Public Enums

    enum PN532_GPIO_Commands : uint8_t {
        AllHigh = 0xBE,
        AllLow = 0x94,
        P31Only = 0x96,
        P33Only = 0x9C,
        P35Only = 0xB4,
        P31_P32 = 0x9E,
        P31_P35 = 0xB6,
        P32_P35 = 0xBC,
        ResetAll = 0x80
    };

    enum SAMConfigMode : uint8_t {
        Normal = 0x01,
        VirtualCard = 0x02,
        WiredCard = 0x03,
        DualCard = 0x04
    };

    enum Mifare_Command : uint8_t {
        ReqA = 0x26,
        WupA = 0x52,
        AuthA = 0x60,
        AuthB = 0x61,
        Read = 0x30,
        Write = 0xA0,
        Transfer = 0xB0,
        Decrement = 0xC0,
        Increment = 0xC1,
        Store = 0xC2,
    };

#pragma endregion

    // PN532 Hardware Functions
    void Configure(RFConfigData* rfParams = nullptr, uint8_t numRFParams = 0, 
        PN532_Params params = PN532_Params(), SAMConfigMode config = Normal);
    uint32_t GetFirmwareVersion(void);
    uint8_t ReadRegister(uint16_t registerAddress, uint8_t* buffer);
    uint8_t WriteRegister(uint16_t registerAddress, uint8_t newValue);
    uint8_t ReadGPIO(uint8_t* buffer);
    uint8_t WriteGPIO(PN532_GPIO_Commands command);
    uint8_t EnterPowerDownMode();

    // Mifare Classic Helper functions
    uint8_t FindTargetByUID(uint8_t* targetUID);
    uint8_t ScanForTargets(MifareClassic* tagsList, uint8_t maxExpectedTargets = 1, uint8_t maxRetries = 1);
    uint8_t QuickAccessMifareTarget(uint8_t* targetUID, uint8_t blockNumber, Mifare_Command command, uint8_t* dataBuffer);
    uint8_t ReadDataBlock(uint8_t indexedTagNumber, uint8_t blockNumber, uint8_t* responseBuffer);
    uint8_t WriteDataBlock(uint8_t indexedTagNumber, uint8_t blockNumber, uint8_t* dataBuffer);
    uint8_t HaltActiveTarget(int8_t indexedTagNumber = -1, bool keepDataInRegister = false);

private:

#pragma region Private Enums

    enum Constants : uint8_t {
        Max_PN532_Targets   = 2,
        Max_Buffer_Size     = 32,
        Auth_Key_Size       = 6,
        Ack_Timeout         = 10,
        PN532_I2C_Address   = (0x48 >> 1)
    };
    
    enum PN532_Command : uint8_t {
        diagnose            = 0x00,
        getFirmwareVersion  = 0x02,
        getGeneralStatus    = 0x04,
        readRegister        = 0x06,
        writeRegister       = 0x08,
        readGPIO            = 0x0C,
        writeGPIO           = 0x0E,
        setSerialBaudRate   = 0x10,
        setParams           = 0x12,
        SAMConfig           = 0x14,
        powerDown           = 0x16,
        RFConfig            = 0x32,
        RFRegulationTest    = 0x58,
        inJumpForDEP        = 0x56,
        inJumpForPSL        = 0x46,
        inListPassiveTarget = 0x4A,
        inATR               = 0x50,
        inPSL               = 0x4E,
        inDataExchange      = 0x40,
        inCommunicateThru   = 0x42,
        inDeselect          = 0x44,
        inRelease           = 0x52,
        inSelect            = 0x54,
        inAutoPoll          = 0x60
    };

    // From PN532 Documentation pg.67-68
    enum PN532_Error : uint8_t {
        Success                 = 0x00,
        Timeout                 = 0x01,
        CRC_Error               = 0x02,
        Partiy_Error            = 0x03,
        Passive_BadBitCount     = 0x04,
        Framing_Error           = 0x05,
        Abnormal_BitCollision   = 0x06,
        Buffer_Overflow         = 0x07,
        RFBuffer_Overflow       = 0x09,
        RFField_Timeout         = 0x0A,
        RF_Protocol             = 0x0B,
        Temperature_Error       = 0x0D,
        InternalBuffer_Overflow = 0x0E,
        Invalid_Param           = 0x10,
        DEP_Invalid_Command     = 0x12,
        DEP_Invalid_Format      = 0x13,
        Mifare_AuthError        = 0x14,
        Incorrect_UIDByte       = 0x23,
        DEP_Invalid_State       = 0x25,
        Operation_NotAllowed    = 0x26,
        Invalid_Context         = 0x27,
        Released                = 0x29,
        Not_Expected_Card       = 0x2A,
        Card_Disappeared        = 0x2B,
        DEP_MissMatch           = 0x2C,
        OverCurrent_Event       = 0x2D,
        DEP_NoNAD               = 0x2E,
        SyntaxError             = 0x7F,

        // Added for extra debugging, not in official documentation
        InvalidACK              = 0x80,
        ChecksumError           = 0x81,
        DataPacketTooLarge      = 0x82,
        NoTagFound              = 0x83,
        Trailer_Block           = 0x84
    };

    enum PN532_GPIO : uint8_t {
        ValidationBit = 0x08,
        P30 = 0,
        P31 = 1,
        P32 = 2,
        P33 = 3,
        P34 = 4,
        P35 = 5
    };

    enum Tag_Type : uint8_t {
        Mifare = 0x00,
        Felica = 0x01
    };

    enum NFC_TransferBytes : uint8_t {
        PrePostamble    = 0x00,
        StartCode1      = 0x00,
        StartCode2      = 0xFF,
        HostToPN532     = 0xD4,
        PN532ToHost     = 0xD5
    };

#pragma endregion

    TwoWire* _wire;
    MifareClassic _inListedTags[2];
    uint8_t _dataBuffer[Max_Buffer_Size];
    uint16_t _i2cTimeout = 1000;

    // Data Buffer Preparation
    uint8_t SetParameters(PN532_Params params);
    uint8_t ConfigureSAM(SAMConfigMode config);
    uint8_t SetRFConfiguration(RFConfigData data);
    uint8_t AuthenticateBlock(uint8_t indexedTagNumber, uint8_t blockNumber);
    uint8_t InListPassiveTarget(uint8_t maxTargets, uint8_t* knownUID = nullptr, uint8_t uidLength = 0);
    uint8_t InDataExchange(uint8_t target, Mifare_Command command, uint8_t* data, uint8_t dataLength);
    uint8_t InCommunicateThrough(uint8_t* data, uint8_t dataLength);

    uint8_t SendRecieveDataBuffer(uint8_t headerLength, uint8_t* data = 0, uint8_t dataLength = 0);

    // I2C Communication
    void Wakeup();
    uint8_t WriteI2C(const uint8_t* header, uint8_t hlen, bool useFullAck = false, const uint8_t* body = 0, uint8_t blen = 0);
    uint8_t ReadI2C(uint8_t* buffer);
    uint8_t ReadAckFrame(bool useFullAck);

    // Helper Functions
    bool IsUniqueUID(MifareClassic* tagsList, uint8_t* uid);
    uint8_t GetNextEmptyIndex(MifareClassic* tagList);
};

#endif
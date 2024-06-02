#include "Arduino.h"
#include "PN532_I2C_Lite.h"
#include "PN532_Logger.h"

PN532_I2C::PN532_I2C(TwoWire& wire, uint16_t timeout) {
    _wire = &wire;
    _i2cTimeout = timeout;
}

#pragma region PN532 Hardware Functions

/*!
    @brief  Configure I2C, Hardware operating Params, and perform RF Test
    @param  initI2C     Optional: Initialize I2C
    @param  rfParams    Optional: List of RFConfigData to set
    @param  numRFParams The number of RF Parameters to be set
    @param  params      Optional: Sets default operating Parameters
    @param  samConfig   Optional: Sets SAM configuration, default = Bypass
    @returns Status code
*/
uint8_t PN532_I2C::Configure(bool initI2C, RFConfigData* rfParams, uint8_t numRFParams, PN532_Params params, SAMConfigMode samConfig) {
    
    if(initI2C) _wire->begin();
    Wakeup();

    memset(_dataBuffer, 0, Max_Buffer_Size);

    // TODO: Get current configuration for comparison

    uint8_t status = SetParameters(params);
    if (status != PN532_Error::Success) {
        LOG_ERROR("SetParameters()", status);
        return status;
    }

    status = ConfigureSAM(samConfig);
    if (status != PN532_Error::Success) {
        LOG_ERROR("ConfigureSAM()", status);
        return status;
    }

    if (rfParams) {
        for (uint8_t i = 0; i < numRFParams; i++) {
            status = SetRFConfiguration(rfParams[i]);
            if (status != PN532_Error::Success) {
                LOG_ERROR("SetRFConfiguration()", status);
                return status;
            }
        }
    }

    return PerformRFTest();
}

/*!
    @brief  Checks the firmware version of the PN5xx chip
    @returns  The chip's firmware version and ID
*/
uint32_t PN532_I2C::GetFirmwareVersion(void) {

    _dataBuffer[0] = PN532_Command::getFirmwareVersion;

    int8_t status = SendRecieveDataBuffer(1);
    if (status != PN532_Error::Success) return 0;

    uint32_t response;

    response = _dataBuffer[0];
    response <<= 8;
    response |= _dataBuffer[1];
    response <<= 8;
    response |= _dataBuffer[2];
    response <<= 8;
    response |= _dataBuffer[3];

    return response;
}

/*!
    @brief    Read a PN532_I2C register.
    @param    registerAddress   The 16-bit register address.
    @param    buffer            Buffer to write the register value to
    @returns  Status code
*/
uint8_t PN532_I2C::ReadRegister(uint16_t registerAddress, uint8_t* buffer) {

    _dataBuffer[0] = PN532_Command::readRegister;
    _dataBuffer[1] = (registerAddress >> 8) & 0xFF;
    _dataBuffer[2] = registerAddress & 0xFF;

    int8_t status = SendRecieveDataBuffer(3);
    if (status == PN532_Error::Success) {
        *buffer = _dataBuffer[0];
    }

    return status;
}

/*!
    @brief    Write to a PN532_I2C register.
    @param    registerAddress   The 16-bit register address.
    @param    newValue          The 8-bit value to write.
    @returns  Status code
*/
uint8_t PN532_I2C::WriteRegister(uint16_t registerAddress, uint8_t newValue) {

    _dataBuffer[0] = PN532_Command::writeRegister;
    _dataBuffer[1] = (registerAddress >> 8) & 0xFF;
    _dataBuffer[2] = registerAddress & 0xFF;
    _dataBuffer[3] = newValue;

    return SendRecieveDataBuffer(4);
}

/*!
    @brief    Reads the state of the PN532_I2C's GPIO pins
    @params   buffer  Buffer to write data to
    @returns  Status code
*/
uint8_t PN532_I2C::ReadGPIO(uint8_t* buffer) {

    _dataBuffer[0] = PN532_Command::readGPIO;

    uint8_t status = SendRecieveDataBuffer(1);
    if (status == PN532_Error::Success) {
        /* READGPIO response without prefix and suffix should be in the following format:

        byte            Description
        -------------   ------------------------------------------
        b0              P3 GPIO Pins
        b1              P7 GPIO Pins (not used ... taken by I2C)
        b2              Interface Mode Pins (not used ... bus select pins) */

        LOG("P3 GPIO: "); LOG_HEX(_dataBuffer[7]);
        LOG("P7 GPIO: "); LOG_HEX(_dataBuffer[8]);
        LOG("I0I1 GPIO: "); LOG_HEX(_dataBuffer[9]);
        LOG("\n");

        *buffer = _dataBuffer[0];
    }

    return status;
}

/*!
    @brief    Writes an 8-bit value that sets the state of the PN532_I2C's GPIO pins
    @params   command  Enum for which pins to operate on
    @returns  Status code
*/
uint8_t PN532_I2C::WriteGPIO(PN532_GPIO_Commands command) {

    _dataBuffer[0] = PN532_Command::writeGPIO;
    _dataBuffer[1] = PN532_GPIO::ValidationBit | command;
    _dataBuffer[2] = 0x00;

    LOG("Writing P3 GPIO: "); LOG_HEX(_dataBuffer[1]); LOG("\n");

    return SendRecieveDataBuffer(3);
}

// TODO: This is a very basic implementation that can be improved
uint8_t PN532_I2C::EnterPowerDownMode() {

    _dataBuffer[0] = PN532_Command::powerDown;
    _dataBuffer[1] = 0x80; // Only respond to I2C wakeup

    uint8_t status = SendRecieveDataBuffer(2);
    delay(2); // PN532 needs ~1ms to completely enter Power Down

    return status;
}

#pragma endregion

#pragma region Mifare Classic Helper Functions

/*!
    @brief    Searches RF Field for target with the specified UID
    @param    targetUID    The UID of the tag to search for
    @returns  Status code
*/
uint8_t PN532_I2C::FindTargetByUID(uint8_t* targetUID) {
    return InListPassiveTarget(1, targetUID, sizeof(targetUID));
}

/*!
    @brief    Scans for available tags and then attempts to add them to a list of NFC Tags
    @param    tagsList            List to be populated with NFC tag data
    @param    maxExpectedTargets  Total number of expected targets to find in field simultaneously
    @param    maxRetries          Max number of times to search the field
    @returns  Number of unique tags found
*/
// TODO: Error Handling can be improved, improve speed and accuracy
// BUG: Tags are held in PN532 memory making them not scanable on sequential calls
uint8_t PN532_I2C::ScanForTargets(MifareClassic* tagsList, uint8_t maxExpectedTargets, uint8_t maxRetries) {

    uint8_t tagCount = 0;
    do {
        uint8_t status = InListPassiveTarget(2);
        if (status != PN532_Error::Success) continue;

        for (uint8_t i = 0; i < _dataBuffer[0]; i++) {
            if (!IsUniqueUID(tagsList, _inListedTags[i].UID)) continue;

            uint8_t emptyArrayIndex = GetNextEmptyIndex(tagsList);
            if (emptyArrayIndex == 255) break;

            tagsList[emptyArrayIndex].Initialized = true;
            memcpy(tagsList[emptyArrayIndex].UID, _inListedTags[i].UID, _inListedTags[i].UIDLen);
            tagCount++;
        }

        HaltActiveTarget(-1, true);
        if (tagCount >= maxExpectedTargets) break;

    } while (maxRetries-- > 0);

    return tagCount;
}

/*!
    @brief    Scans RF Field for designated tag, authenticates and performs a Read/Write on specified block
    @param    targetUID       Target to search for and operate on
    @param    blockNumber     Block number to authenticate and read from/write to
    @param    command         Only Supports Read or Write commands
    @param    dataBuffer      Buffer to read to, or write from
    @returns  Status code
*/
uint8_t PN532_I2C::QuickAccessMifareTarget(uint8_t* targetUID, uint8_t blockNumber, Mifare_Command command, uint8_t* dataBuffer) {

    uint8_t status = InListPassiveTarget(1, targetUID, sizeof(targetUID));
    if (status != PN532_Error::Success) return status;

    switch (command) {
        case PN532_I2C::Read:
            status = ReadDataBlock(0, blockNumber, dataBuffer);
            break;
        case PN532_I2C::Write:
            status = WriteDataBlock(0, blockNumber, dataBuffer);
            break;
        default:
            status = PN532_Error::SyntaxError;
            break;
    }

    return status != PN532_Error::Success
        ? status
        : HaltActiveTarget();
}

/*!
    @brief    Authenticates, then reads a block of the Mifare Tag's memory
    @param    indexedTagNumber  The index of the tag to read
    @param    blockNumber       Block number to authenticate and read from/write to
    @param    responseBuffer    Buffer to read the data to
    @returns  Status code
*/
uint8_t PN532_I2C::ReadDataBlock(uint8_t indexedTagNumber, uint8_t blockNumber, uint8_t* responseBuffer) {

    uint8_t status = PN532_Error::Success;
    if (_inListedTags[indexedTagNumber].AuthorizedBlock != blockNumber) {
        status = AuthenticateBlock(indexedTagNumber, blockNumber);
    }

    if (status != PN532_Error::Success) return status;
    
    status = InDataExchange(indexedTagNumber, Mifare_Command::Read, &blockNumber, 1);
    if (status != PN532_Error::Success) {
        LOG_ERROR("ReadDataBlock()", status);
        return status;
    }

    memcpy(responseBuffer, _dataBuffer + 1, 16);
    return status;
}

/*!
    @brief    Authenticates, then writes to a block of the Mifare Tag's memory
    @param    indexedTagNumber  The index of the tag to read
    @param    blockNumber       Block number to authenticate and read from/write to
    @param    dataBuffer        Buffer of data to write to the Mifare
    @returns  Status code
*/
uint8_t PN532_I2C::WriteDataBlock(uint8_t indexedTagNumber, uint8_t blockNumber, uint8_t* dataBuffer) {

    if (blockNumber % 16 == 0) {
        LOG_ERROR("WriteDataBlock()", PN532_Error::Trailer_Block);
        return PN532_Error::Trailer_Block;
    }

    uint8_t status = PN532_Error::Success;
    if (_inListedTags[indexedTagNumber].AuthorizedBlock != blockNumber) {
        status = AuthenticateBlock(indexedTagNumber, blockNumber);
    }

    if (status != PN532_Error::Success) return status;
    
    uint8_t buffer[17]{};
    buffer[0] = blockNumber;
    memcpy(buffer + 1, dataBuffer, 16);

    status = InDataExchange(indexedTagNumber, Mifare_Command::Write, buffer, 17);
    if (status != PN532_Error::Success) {
        LOG_ERROR("WriteDataBlock()", status);
    }

    return status;
}

/*!
    @brief      Deslects tags in Register from active communication with the PN532 using HALTA
    @param      indexedTagNumber    The indexed number to halt, default halts all tags
    @param      keepDataInRegister  Whether to keep relevant number in the register
    @returns    Status code
*/
uint8_t PN532_I2C::HaltActiveTarget(int8_t indexedTagNumber, bool keepDataInRegister) {

    _dataBuffer[0] = keepDataInRegister ? inDeselect : inRelease;
    _dataBuffer[1] = indexedTagNumber + 1; // Convert to logical number

    return SendRecieveDataBuffer(2);
}

#pragma endregion

#pragma region Data Buffer Preparation

uint8_t PN532_I2C::PerformRFTest(void) {

    _dataBuffer[0] = PN532_Command::RFRegulationTest;
    _dataBuffer[1] = Tag_Type::Mifare;
    return WriteI2C(_dataBuffer, 2);
}

// TODO: Can we remove the strings unless using a deeper debug? Should we?
uint8_t PN532_I2C::SetParameters(PN532_Params params) {

    LOG("Setting PN532 Parameters\n");
    byte paramsBit = 0x00;

    paramsBit ^= (params.useNAD << 0);
    LOG("Use NAD: "); LOG(params.useNAD ? "Yes" : "No"); LOG("\n");

    paramsBit ^= (params.useDID << 1);
    LOG("Use DID: "); LOG(params.useDID ? "Yes" : "No"); LOG("\n");

    paramsBit ^= (params.useAutoATR << 2);
    LOG("Use AutoATR: "); LOG(params.useAutoATR ? "Yes" : "No"); LOG("\n");

    paramsBit ^= (params.useAutoRATS << 4);
    LOG("Use AutoRATS: "); LOG(params.useAutoRATS ? "Yes" : "No"); LOG("\n");

    paramsBit ^= (params.enablePICCMode << 5);
    LOG("Enable PICC Mode: "); LOG(params.enablePICCMode ? "Yes" : "No"); LOG("\n");

    paramsBit ^= (params.suppressPrePostAmble << 6);
    LOG("Suppress Pre/PostAmble: "); LOG(params.suppressPrePostAmble ? "Yes" : "No"); LOG("\n\n");

    _dataBuffer[0] = PN532_Command::setParams;
    _dataBuffer[1] = paramsBit;

    WriteI2C(_dataBuffer, 2);
    _suppressPrePostAmble = params.suppressPrePostAmble;
    return ReadI2C(_dataBuffer);
}

/*!
    @brief    Configures the SAM (Secure Access Module)
    @params   config    The configuration mode pg. 89
    @returns  Status Code
*/
uint8_t PN532_I2C::ConfigureSAM(SAMConfigMode config) {

    _dataBuffer[0] = PN532_Command::SAMConfig;
    _dataBuffer[1] = config;
    _dataBuffer[2] = 0x0A; // timeout 50ms * 10ms
    _dataBuffer[3] = 0x01; // use IRQ pin!

    return SendRecieveDataBuffer(4);
}

/*!
    @brief    Sets RF Parameters for the PN532
    @param    configuration     The configuration mode pg. 89
    @param    data              The data structure containing the parameters
    @returns  Status Code
*/
uint8_t PN532_I2C::SetRFConfiguration(RFConfigData data) {

    _dataBuffer[0] = PN532_Command::RFConfig;
    _dataBuffer[1] = data.GetConfigItemType();
    memcpy(_dataBuffer + 2, data.ConfigData, data.DataLength);

    return SendRecieveDataBuffer(2 + data.DataLength);
}

/*!
    @brief    Tries to authenticate a block of memory on a MIFARE card using AuthA
    @param    indexedTagNumber    0 Indexed number (0 or 1) of the Tag held in memory
    @param    blockNumber         The block number to authenticate.
    @returns  Status code
*/
uint8_t PN532_I2C::AuthenticateBlock(uint8_t indexedTagNumber, uint8_t blockNumber) {

    uint8_t dataBuffer[14];
    uint8_t dataLength = 1 + (uint8_t)Auth_Key_Size + _inListedTags[indexedTagNumber].UIDLen;

    dataBuffer[0] = blockNumber;
    memcpy(dataBuffer + 1, _inListedTags[indexedTagNumber].AuthKey, (uint8_t)Auth_Key_Size);
    memcpy(dataBuffer + 7, _inListedTags[indexedTagNumber].UID, _inListedTags[indexedTagNumber].UIDLen);

    uint8_t status = InDataExchange(indexedTagNumber, Mifare_Command::AuthA, dataBuffer, dataLength);
    if (status != PN532_Error::Success) {
        LOG_ERROR("AuthenticateBlock()", status);
        return status;
    }

    _inListedTags[indexedTagNumber].AuthorizedBlock = blockNumber;
    return status;
}

/*!
    @brief      Searches field for valid target and moves them into Active state, then adds
                them to the collected tags array.
    @param      maxTargets      Maximum number of targets to inList. PN532 max is 2
    @param      knownUID        Optional: target UID if already known
    @param      uidLength       Optional: length of target UID
    @returns    Status code
*/
uint8_t PN532_I2C::InListPassiveTarget(uint8_t maxTargets, uint8_t* knownUID, uint8_t uidLength) {

    if (maxTargets > Max_PN532_Targets) {
        LOG("Max 2 Targets!\n");
        maxTargets = Max_PN532_Targets;
    }

    _dataBuffer[0] = PN532_Command::inListPassiveTarget;
    _dataBuffer[1] = maxTargets;
    _dataBuffer[2] = Tag_Type::Mifare;

    if (knownUID) {
        memcpy(_dataBuffer + 3, knownUID, uidLength);
    }

    uint8_t status = SendRecieveDataBuffer(3 + uidLength);
    if (status != PN532_Error::Success) return status;

    /*
      byte            Description
      -------------   ------------------------------------------
      b0              Tags Found
      b1              Tag Number
      b2..3           SENS_RES
      b4              SEL_RES
      b5              NFCID Length
      b6..NFCIDLen    NFCID
    */

    if (_dataBuffer[0] <= 0) {
        LOG_ERROR("InListPassiveTarget()", PN532_Error::NoTagFound);
        return PN532_Error::NoTagFound;
    }

    uint8_t tag1DataLength = 5 + _dataBuffer[5];
    for (uint8_t i = 0; i < _dataBuffer[0]; i++) {
        uint8_t uidLocation = 6 + (tag1DataLength * i);
        memcpy(_inListedTags[i].UID, _dataBuffer + uidLocation, _inListedTags[i].UIDLen);

        _inListedTags[i].AuthorizedBlock = 0;
    }

    return status;
}

/*!
    @brief   Exchanges an APDU with one of the inListed Tags
    @param   indexedTargetNumber     The indexed tag number to interact with
    @param   command                 The Mifare command to send
    @param   data                    Pointer to data to send
    @param   dataLength              Length of the data to send
    @return  Status code
*/
uint8_t PN532_I2C::InDataExchange(uint8_t indexedTargetNumber, Mifare_Command command, uint8_t* data, uint8_t dataLength) {

    if (indexedTargetNumber > 1) {
        LOG("[WARN] Use indexed tag number!");
        indexedTargetNumber = 1;
    }
    
    _dataBuffer[0] = PN532_Command::inDataExchange;
    _dataBuffer[1] = indexedTargetNumber + 1;
    _dataBuffer[2] = command;

    uint8_t success = SendRecieveDataBuffer(3, data, dataLength);

    return success == PN532_Error::Success
        ? _dataBuffer[0]
        : success;
}

// TODO: This function doesn't seem to work yet
uint8_t PN532_I2C::InCommunicateThrough(uint8_t* data, uint8_t dataLength) {

    _dataBuffer[0] = PN532_Command::inCommunicateThru;

    uint8_t success = SendRecieveDataBuffer(1, data, dataLength);

    return success == PN532_Error::Success
        ? _dataBuffer[0]
        : success;
}

#pragma endregion

uint8_t PN532_I2C::SendRecieveDataBuffer(uint8_t headerLength, uint8_t* data, uint8_t dataLength) {

    uint8_t status = WriteI2C(_dataBuffer, headerLength, data, dataLength);
    if (status != PN532_Error::Success) {
        LOG_ERROR("WriteI2C()", status);
        return status;
    }

    status = ReadI2C(_dataBuffer);
    if (status != PN532_Error::Success) {
        LOG_ERROR("ReadI2C()", status);
    }

    return status;
}

#pragma region I2C Communication

/*!
    @brief  A delay to ensure the PN532 has woken if it has been asleep
            Documentation on this delay is found on pg. 56-57 for I2C
*/
// TODO: This can be improved to check the IRQ after implementing power down
void PN532_I2C::Wakeup() {
    delay(100);
}

uint8_t PN532_I2C::WriteI2C(const uint8_t* header, uint8_t hlen, const uint8_t* body, uint8_t blen) {

    _wire->beginTransmission(PN532_I2C_Address);

    _wire->write(NFC_TransferBytes::PrePostamble);
    _wire->write(NFC_TransferBytes::StartCode1);
    _wire->write(NFC_TransferBytes::StartCode2);

    uint8_t length = hlen + blen + 1;   // length of data field: TFI + DATA
    _wire->write(length);
    _wire->write(~length + 1);                 // checksum of length

    _wire->write(NFC_TransferBytes::HostToPN532);
    uint8_t sum = NFC_TransferBytes::HostToPN532;    // sum of TFI + DATA

    LOG("write: ");

    for (uint8_t i = 0; i < hlen; i++) {
        if (_wire->write(header[i])) {
            sum += header[i];
            LOG_HEX(header[i]);
        }
        else return PN532_Error::DataPacketTooLarge;
    }

    for (uint8_t i = 0; i < blen; i++) {
        if (_wire->write(body[i])) {
            sum += body[i];
            LOG_HEX(body[i]);
        }
        else return PN532_Error::DataPacketTooLarge;
    }

    uint8_t checksum = ~sum + 1;            // checksum of TFI + DATA
    _wire->write(checksum);
    _wire->write(NFC_TransferBytes::PrePostamble);

    LOG("\n");

    _wire->endTransmission();
    return ReadAckFrame();
}

uint8_t PN532_I2C::ReadI2C(uint8_t* buffer) {

    uint16_t time = 0;

    do {
        uint8_t responseLength = _wire->requestFrom((uint8_t)PN532_I2C_Address, (uint8_t)Max_Buffer_Size);

        if (responseLength <= 0) {
            delay(1);
            time++;
        }

        if (time > _i2cTimeout) return PN532_Error::Timeout;

        if (_wire->read() & 1) break;

    } while (1);

    if (!_suppressPrePostAmble) _wire->read();
    if (NFC_TransferBytes::StartCode1   != _wire->read() ||
        NFC_TransferBytes::StartCode2   != _wire->read()) {

        return PN532_Error::Framing_Error;
    }

    uint8_t length = _wire->read();
    uint8_t checksum = _wire->read();
    if (length > (uint8_t)Max_Buffer_Size) return PN532_Error::Buffer_Overflow;
    if (0 != (uint8_t)(length + checksum)) return PN532_Error::ChecksumError;

    uint8_t frameIdentifier = _wire->read();
    if (frameIdentifier == PN532_Error::SyntaxError) {
        return PN532_Error::SyntaxError;
    }
    else if (frameIdentifier != NFC_TransferBytes::PN532ToHost) {
        return PN532_Error::Framing_Error;
    }

    uint8_t commandCode = _wire->read();
    LOG("read: "); LOG_HEX(commandCode);

    length -= 1; // Remove Frame Identifier byte to get length of data (pg. 28)
    for (uint8_t i = 0; i < length; i++) {
        buffer[i] = _wire->read();
        LOG_HEX(buffer[i]);
    }
    LOG('\n');

    checksum = _wire->read();
    return !checksum ? PN532_Error::Success : PN532_Error::ChecksumError;
}

uint8_t PN532_I2C::ReadAckFrame() {
    
    uint8_t shortAck[] =   { 0, 0xFF, 0, 0xFF };
    uint8_t longAck[] = { 0, 0, 0xFF, 0, 0xFF, 0 };
    
    uint8_t bufferSize = _suppressPrePostAmble ? sizeof(shortAck) : sizeof(longAck);
    uint8_t ackBuf[6]{};

    uint16_t time = 0;
    do {
        if (_wire->requestFrom((uint8_t)PN532_I2C_Address, (uint8_t)(bufferSize + 1))) {
            if (_wire->read() & 1) break;
        }

        delay(1);
        time++;
        if (time > (uint8_t)Ack_Timeout) return PN532_Error::Timeout;

    } while (1);

    for (uint8_t i = 0; i < bufferSize; i++) {
        ackBuf[i] = _wire->read();
    }

    int outcome = _suppressPrePostAmble
        ? memcmp(ackBuf, shortAck, sizeof(shortAck))
        : memcmp(ackBuf, longAck, sizeof(longAck));

    return outcome == PN532_Error::Success
        ? PN532_Error::Success
        : PN532_Error::InvalidACK;
}

#pragma endregion

#pragma region Helper Functions

bool PN532_I2C::IsUniqueUID(MifareClassic* tagsList, uint8_t* uid) {

    for (uint8_t i = 0; i < sizeof(tagsList); i++) {        
        if (!memcmp(tagsList[i].UID, uid, tagsList[i].UIDLen)) return false;
    }

    return true;
}

// TODO: Improve how this handles an array with no empty spaces
uint8_t PN532_I2C::GetNextEmptyIndex(MifareClassic* tagList) {

    if (sizeof(tagList) >= 255) return 255;

    for (uint8_t i = 0; i < sizeof(tagList); i++) {
        if (!tagList[i].Initialized) return i;
    }

    return 255;
}

#pragma endregion
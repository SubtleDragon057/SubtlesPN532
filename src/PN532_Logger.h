#ifndef __PN532_Logger_H__
#define __PN532_Logger_H__
#include "Arduino.h"

//#define DEBUG

#ifdef DEBUG
#define LOG(data)			PN532_Logger.Log(data);
#define LOG_HEX(num)		PN532_Logger.LogHex(num);
#define LOG_INT(num)		PN532_Logger.LogNum(num);
#define LOG_ERROR(location, error)	PN532_Logger.LogError(location, error);
#else
#define LOG(data)
#define LOG_HEX(num)
#define LOG_INT(num)
#define LOG_ERROR(location, error)	PN532_Logger.LogError(location, error);
#endif

static class SubtlesPN532_Logger {
public:

    static void Log(const char* data) {
        Serial.print(data);
    }

    static void LogHex(uint8_t num) {
        Serial.print(' '); Serial.print((num >> 4) & 0x0F, HEX); Serial.print(num & 0x0F, HEX);
    }

    static void LogNum(uint8_t num) {
        Serial.print(' '); Serial.print(num);
    }

    static void LogError(const char* location, uint8_t error) {
        Serial.print("[ERROR] "); Serial.print(location); Serial.print(": ");

#ifdef DEBUG
        Serial.println(GetErrorMessage(error));
#else
        Serial.print("0x");
        Serial.println(error, HEX);
#endif
    }

private:

    static char* GetErrorMessage(uint8_t status) {

#ifdef _DEBUG
        switch (status) {
            case 0x00:      return "Success!";
            case 0x01:      return "(0x01)Timeout";
            case 0x02:      return "(0x02)CRC Error";
            case 0x03:      return "(0x03)Parity Error";
            case 0x04:      return "(0x04)Incorrect Bit Count";
            case 0x05:      return "(0x05)Mifare Framing Error";
            case 0x06:      return "(0x06)Abnormal Bit Collision";
            case 0x07:      return "(0x07)Insufficient Buffer Size";
            case 0x09:      return "(0x09)RF Buffer Overflow";
            case 0x0A:      return "(0x0A)RF Field Timeout";
            case 0x0B:      return "(0x0B)RF Protocol Error";
            case 0x0D:      return "(0x0D)Temperature Error";
            case 0x0E:      return "(0x0E)Internal Buffer Overflow";
            case 0x10:      return "(0x10)Invalid Param";
            case 0x12:      return "(0x12)DEP Invalid Command";
            case 0x13:      return "(0x13)DEP Invalid Format";
            case 0x14:      return "(0x14)Auth Failed";
            case 0x23:      return "(0x23)Incorrect UID Check Byte";
            case 0x25:      return "(0x25)DEP Invalid Device State";
            case 0x26:      return "(0x26)Operation Not Allowed in current Configuration";
            case 0x27:      return "(0x27)Invalid Operation Context";
            case 0x29:      return "(0x29)Initiator released the Target";
            case 0x2A:      return "(0x2A)UID doesn't match expected UID";
            case 0x2B:      return "(0x2B)Previously Activated Card is Gone";
            case 0x2C:      return "(0x2C)DEP ID Mismatch";
            case 0x2D:      return "(0x2D)Overcurrent Event";
            case 0x2E:      return "(0x2E)NAD missing in DEP frame";
            case 0x7F:      return "(0x7F)Syntax Error";
            case 0x80:      return "(0x80)Invalid ACK Timing";
            case 0x81:      return "(0x81)I2C Checksum Error";
            case 0x82:      return "(0x82)Data Packet Too Large";
            case 0x83:      return "(0x83)No Tags Found";
            case 0x84:      return "(0x84)Block is not a Data Block";
            default:        return "(0xFF)Unknown Error";
        }
#else
        return "";
#endif
    }

} PN532_Logger;

static class SubtlesPN532_Logger {
public:

    static void Log(const char* data) {
        Serial.print(data);
    }

    static void LogHex(uint8_t num) {
        Serial.print(' '); Serial.print((num >> 4) & 0x0F, HEX); Serial.print(num & 0x0F, HEX);
    }

    static void LogNum(uint8_t num) {
        Serial.print(' '); Serial.print(num);
    }

    static void LogError(const char* location, uint8_t error) {
        Serial.print("[ERROR] "); Serial.print(location); Serial.print(": ");

#ifdef _DEBUG
        Serial.println(GetErrorMessage(error));
#else
        Serial.print("0x");
        Serial.println(error, HEX);
#endif
    }

private:

    static char* GetErrorMessage(uint8_t status) {

#ifdef _DEBUG
        switch (status) {
            case 0x00:      return "Success!";
            case 0x01:      return "(0x01)Timeout";
            case 0x02:      return "(0x02)CRC Error";
            case 0x03:      return "(0x03)Parity Error";
            case 0x04:      return "(0x04)Incorrect Bit Count";
            case 0x05:      return "(0x05)Mifare Framing Error";
            case 0x06:      return "(0x06)Abnormal Bit Collision";
            case 0x07:      return "(0x07)Insufficient Buffer Size";
            case 0x09:      return "(0x09)RF Buffer Overflow";
            case 0x0A:      return "(0x0A)RF Field Timeout";
            case 0x0B:      return "(0x0B)RF Protocol Error";
            case 0x0D:      return "(0x0D)Temperature Error";
            case 0x0E:      return "(0x0E)Internal Buffer Overflow";
            case 0x10:      return "(0x10)Invalid Param";
            case 0x12:      return "(0x12)DEP Invalid Command";
            case 0x13:      return "(0x13)DEP Invalid Format";
            case 0x14:      return "(0x14)Auth Failed";
            case 0x23:      return "(0x23)Incorrect UID Check Byte";
            case 0x25:      return "(0x25)DEP Invalid Device State";
            case 0x26:      return "(0x26)Operation Not Allowed in current Configuration";
            case 0x27:      return "(0x27)Invalid Operation Context";
            case 0x29:      return "(0x29)Initiator released the Target";
            case 0x2A:      return "(0x2A)UID doesn't match expected UID";
            case 0x2B:      return "(0x2B)Previously Activated Card is Gone";
            case 0x2C:      return "(0x2C)DEP ID Mismatch";
            case 0x2D:      return "(0x2D)Overcurrent Event";
            case 0x2E:      return "(0x2E)NAD missing in DEP frame";
            case 0x7F:      return "(0x7F)Syntax Error";
            case 0x80:      return "(0x80)Invalid ACK Timing";
            case 0x81:      return "(0x81)I2C Checksum Error";
            case 0x82:      return "(0x82)Data Packet Too Large";
            case 0x83:      return "(0x83)No Tags Found";
            case 0x84:      return "(0x84)Block is not a Data Block";
            default:        return "(0xFF)Unknown Error";
        }
#else
        return "";
#endif
    }

} PN532_Logger;

#endif
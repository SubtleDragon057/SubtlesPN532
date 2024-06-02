#ifndef __PN532_Logger_H__
#define __PN532_Logger_H__
#include "Arduino.h"

//#define DEBUG

#ifdef DEBUG
#define LOG(data)			Serial.print(data)
#define LOG_HEX(num)		Serial.print(' '); Serial.print((num>>4)&0x0F, HEX); Serial.print(num&0x0F, HEX)
#define LOG_INT(num)		Serial.print(' '); Serial.print(num)
#define LOG_ERROR(location, error)	LogErrorMessage(location, error)

void LogErrorMessage(String location, uint8_t status) {

	char* errorMessage;
	switch (status) {
		case 0x00:
			errorMessage = "Success!";
			break;
		case 0x01:
			errorMessage = "(0x01)Timeout";
			break;
		case 0x02:
			errorMessage = "(0x02)CRC Error";
			break;
		case 0x03:
			errorMessage = "(0x03)Parity Error";
			break;
		case 0x04:
			errorMessage = "(0x04)Incorrect Bit Count";
			break;
		case 0x05:
			errorMessage = "(0x05)Mifare Framing Error";
			break;
		case 0x06:
			errorMessage = "(0x06)Abnormal Bit Collision";
			break;
		case 0x07:
			errorMessage = "(0x07)Insufficient Buffer Size";
			break;
		case 0x09:
			errorMessage = "(0x09)RF Buffer Overflow";
			break;
		case 0x0A:
			errorMessage = "(0x0A)RF Field Timeout";
			break;
		case 0x0B:
			errorMessage = "(0x0B)RF Protocol Error";
			break;
		case 0x0D:
			errorMessage = "(0x0D)Temperature Error";
			break;
		case 0x0E:
			errorMessage = "(0x0E)Internal Buffer Overflow";
			break;
		case 0x10:
			errorMessage = "(0x10)Invalid Param";
			break;
		case 0x12:
			errorMessage = "(0x12)DEP Invalid Command";
			break;
		case 0x13:
			errorMessage = "(0x13)DEP Invalid Format";
			break;
		case 0x14:
			errorMessage = "(0x14)Auth Failed";
			break;
		case 0x23:
			errorMessage = "(0x23)Incorrect UID Check Byte";
			break;
		case 0x25:
			errorMessage = "(0x25)DEP Invalid Device State";
			break;
		case 0x26:
			errorMessage = "(0x26)Operation Not Allowed in current Configuration";
			break;
		case 0x27:
			errorMessage = "(0x27)Invalid Operation Context";
			break;
		case 0x29:
			errorMessage = "(0x29)Initiator released the Target";
			break;
		case 0x2A:
			errorMessage = "(0x2A)UID doesn't match expected UID";
			break;
		case 0x2B:
			errorMessage = "(0x2B)Previously Activated Card is Gone";
			break;
		case 0x2C:
			errorMessage = "(0x2C)DEP ID Mismatch";
			break;
		case 0x2D:
			errorMessage = "(0x2D)Overcurrent Event";
			break;
		case 0x2E:
			errorMessage = "(0x2E)NAD missing in DEP frame";
			break;
		case 0x7F:
			errorMessage = "(0x7F)Syntax Error";
			break;
		case 0x80:
			errorMessage = "(0x80)Invalid ACK Timing";
			break;
		case 0x81:
			errorMessage = "(0x81)I2C Checksum Error";
			break;
		case 0x82:
			errorMessage = "(0x82)Data Packet Too Large";
			break;
		case 0x83:
			errorMessage = "(0x83)No Tags Found";
			break;
		case 0x84:
			errorMessage = "(0x84)Block is not a Data Block";
			break;
		default:
			errorMessage = "Unknown Error Occurred!";
			break;
	}

	Serial.printf("Error in %s: %s\n", location.c_str(), errorMessage);
}
#else
#define LOG(data)
#define LOG_HEX(num)
#define LOG_INT(num)
#define LOG_ERROR(location, error)	Serial.printf("Error in %s: %u\n", location, error)
#endif

#endif
/*
 * Copyright (C) 2011 Rodolfo Giometti <giometti@linux.it>
 * Copyright (C) 2011 CAEN RFID <info@caenrfid.it>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License as published by the Free Software Foundation version 2
 *  of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this package; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef _CAENRFID_OLD_H
#define _CAENRFID_OLD_H

#include <dlfcn.h>

/*
 * Misc macros
 */

#ifndef _YES_I_KNOW_USING_OLD_CAENRFID_API_IS_EVIL
#define __deprecated			__attribute__ ((deprecated))
#else
#define __deprecated			/* void */
#endif

/*
 * Library's defines
 */

#define MAX_ID_LENGTH			CAENRFID_ID_LEN
#define MAX_LOGICAL_SOURCE_NAME		CAENRFID_SOURCE_NAME_LEN
#define MAX_READPOINT_NAME		CAENRFID_READPOINT_NAME_LEN

/*
 * Error codes
 */

typedef enum {
	CAENRFID_StatusOK		= -CAENRFID_ERR_OK,
	CAENRFID_TooManyClientsError	= -CAENRFID_ERR_TOO_MANY_CLIENTS,
	CAENRFID_PortError		= -CAENRFID_ERR_UNKNOW_PORT,
	CAENRFID_LibraryError		= -CAENRFID_ERR_WINSOCK,
	CAENRFID_SocketError		= -CAENRFID_ERR_SOCKET,
	CAENRFID_InvalidHandleError	= -CAENRFID_ERR_INVALID_HANDLE,
	CAENRFID_OutOfMemoryError	= -CAENRFID_ERR_OUT_OF_MEM,
	CAENRFID_CommunicationError	= -CAENRFID_ERR_COMMUNICATION,
	CAENRFID_CommunicationTimeOut	= -CAENRFID_ERR_TIMEOUT,
	CAENRFID_ChannelExist		= -CAENRFID_ERR_CHANNEL_EXIST,
	CAENRFID_GenericError		= -CAENRFID_ERR_GENERIC,
	CAENRFID_InvalidParam		= -CAENRFID_ERR_INVALID_PARAM,
	CAENRFID_ReaderBusy		= -CAENRFID_ERR_READER_BUSY,
	CAENRFID_EOF			= -CAENRFID_ERR_EOF,
} CAENRFIDErrorCodes;

/*
 * Library's types
 */

typedef enum {
	RS232				= CAENRFID_PORT_RS232,
	RS485				= CAENRFID_PORT_RS485,
	TCP				= CAENRFID_PORT_TCP,
	USB				= CAENRFID_PORT_USB,
} caenrfid_port_t;

typedef struct caenrfid_handle caenrfid_handle_t;

typedef enum {
	ISO18000_6B			= CAENRFID_PROTOCOL_ISO18000_6B,
	EPC_C1G1			= CAENRFID_PROTOCOL_EPC_C1G1,
	EM				= CAENRFID_PROTOCOL_EM,
	EPC_C1G2			= CAENRFID_PROTOCOL_EPC_C1G2,
	MULTIPROTOCOL			= CAENRFID_PROTOCOL_MULTIPROTOCOL,
	EPC119				= CAENRFID_PROTOCOL_EPC119,
} caenrfid_protocol_t;

typedef enum {
	CONFIG_READCYCLE		= CAENRFID_SRC_CFG_READCYCLE,
	CONFIG_OBSERVEDTHRESHOLD	= CAENRFID_SRC_CFG_OBSERVEDTHRESHOLD,
	CONFIG_LOSTTHRESHOLD		= CAENRFID_SRC_CFG_LOSTTHRESHOLD,
	CONFIG_G2_Q_VALUE		= CAENRFID_SRC_CFG_G2_Q_VALUE,
	CONFIG_G2_SESSION		= CAENRFID_SRC_CFG_G2_SESSION,
	CONFIG_G2_TARGET		= CAENRFID_SRC_CFG_G2_TARGET,
	CONFIG_G2_SELECTED		= CAENRFID_SRC_CFG_G2_SELECTED,
	CONFIG_ISO18006B_DESB           = CAENRFID_SRC_CFG_ISO18006B_DESB,
} CAENRFID_SOURCE_Parameter;

typedef struct {
	unsigned char	ID[MAX_ID_LENGTH];
	short		Length;
	char		LogicalSource[MAX_LOGICAL_SOURCE_NAME];
	char		ReadPoint[MAX_READPOINT_NAME];
	enum caenrfid_protocol	Type;
	short		RSSI;
} CAENRFIDTag;

/*
 * Old library's functions
 */

static inline int __deprecated CAENRFID_FlagInventoryTag(caenrfid_handle_t *handle,
			char *SourceName,
			char *Mask, unsigned char MaskLength,
			unsigned char Position,
			unsigned char flag,
			CAENRFIDTag **Receive, int *Size)
{
	struct caenrfid_tag *tags;
	size_t len;
	int i, ret;

	ret = caenrfid_complex_inventory(handle, SourceName,
					(uint8_t *) Mask, MaskLength,
					Position, flag,
					&tags, &len);
	if (ret != 0)
		return ret;

	/* Map the new tag struct into the old one */
	*Receive = malloc(sizeof(CAENRFIDTag) * len);
	if (!*Receive)
		return CAENRFID_OutOfMemoryError;

	for (i = 0; i < len; i++) {
		memcpy((*Receive)[i].ID, tags[i].id, tags[i].len);
		(*Receive)[i].Length = tags[i].len;
		strcpy((*Receive)[i].LogicalSource, tags[i].source);
		strcpy((*Receive)[i].ReadPoint, tags[i].readpoint);
		(*Receive)[i].Type = tags[i].type;
		(*Receive)[i].RSSI = tags[i].rssi;
	}
	*Size = len;
	free(tags);

	return ret;
}

static inline int __deprecated CAENRFID_InventoryTag(caenrfid_handle_t *handle,
			char *SourceName, CAENRFIDTag **Receive, int *Size)
{
	return CAENRFID_FlagInventoryTag(handle, SourceName,
					NULL, 0, 0, 0,
					Receive, Size);
}

static inline void __deprecated CAENRFID_FreeTagsMemory(CAENRFIDTag **Tags)
{
	if (*Tags != NULL)
		free(*Tags);
}

static inline int __deprecated CAENRFID_AddReadPoint(caenrfid_handle_t *handle,
				char *SourceName, char *ReadPoint)
{
	return caenrfid_add_readpoint(handle, SourceName, ReadPoint);
}

static inline int __deprecated CAENRFID_RemoveReadPoint(caenrfid_handle_t *handle,
				char *SourceName, char *ReadPoint)
{
	return caenrfid_remove_readpoint(handle, SourceName, ReadPoint);
}

static inline int __deprecated CAENRFID_isReadPointPresent(caenrfid_handle_t *handle,
				char *ReadPoint, char *SourceName,
				short *isPresent)
{
	return caenrfid_check_readpoint(handle, ReadPoint, SourceName,
					(uint16_t *) isPresent);
}

static inline int __deprecated CAENRFID_GetFWRelease(caenrfid_handle_t *handle,
						char *FwRel)
{
        int ret;

        ret = caenrfid_get_fw_release(handle, FwRel, 200);
        if (ret < 0)
                return ret;

        return CAENRFID_StatusOK;
}

static inline int __deprecated CAENRFID_Read_C1G2(caenrfid_handle_t *handle,
				CAENRFIDTag *ID, short membank, int Address,
				int Length, void *Data, int password)
{
	struct caenrfid_tag tag;

	/* Map the old tag struct into the new one */
	memcpy(tag.id, ID->ID, ID->Length);
	tag.len = ID->Length;
	strcpy(tag.source, ID->LogicalSource);
	strcpy(tag.readpoint, ID->ReadPoint);
	tag.type = ID->Type;
	tag.rssi = ID->RSSI;

	return caenrfid_g2_read_tag(handle, &tag, membank, Address, Length,
                                        (uint8_t *) Data, password);
}

static inline int __deprecated CAENRFID_Write_C1G2(caenrfid_handle_t *handle,
				CAENRFIDTag *ID, short membank, int Address,
				int Length, void *Data, int password)
{
	struct caenrfid_tag tag;

	/* Map the old tag struct into the new one */
	memcpy(tag.id, ID->ID, ID->Length);
	tag.len = ID->Length;
	strcpy(tag.source, ID->LogicalSource);
	strcpy(tag.readpoint, ID->ReadPoint);
	tag.type = ID->Type;
	tag.rssi = ID->RSSI;

	return caenrfid_g2_write_tag(handle, &tag, membank, Address, Length,
                                        (uint8_t *) Data, password);
}

static inline int __deprecated CAENRFID_Lock_C1G2(caenrfid_handle_t *handle,
				CAENRFIDTag *ID, int payload, int password)
{
	struct caenrfid_tag tag;

	/* Map the old tag struct into the new one */
	memcpy(tag.id, ID->ID, ID->Length);
	tag.len = ID->Length;
	strcpy(tag.source, ID->LogicalSource);
	strcpy(tag.readpoint, ID->ReadPoint);
	tag.type = ID->Type;
	tag.rssi = ID->RSSI;

	return caenrfid_g2_lock_tag(handle, &tag, payload, password);
}

static inline int __deprecated CAENRFID_KillTag_C1G2(caenrfid_handle_t *handle,
				CAENRFIDTag *ID, int password)
{
	struct caenrfid_tag tag;

	/* Map the old tag struct into the new one */
	memcpy(tag.id, ID->ID, ID->Length);
	tag.len = ID->Length;
	strcpy(tag.source, ID->LogicalSource);
	strcpy(tag.readpoint, ID->ReadPoint);
	tag.type = ID->Type;
	tag.rssi = ID->RSSI;

	return caenrfid_g2_kill_tag(handle, &tag, password);
}

static inline int __deprecated CAENRFID_GetPower(caenrfid_handle_t *handle,
				unsigned int *power)
{
	return caenrfid_get_power(handle, (uint32_t *) power);
}

static inline int __deprecated CAENRFID_SetPower(caenrfid_handle_t *handle,
				unsigned int Power)
{
	return caenrfid_set_power(handle, (uint32_t) Power);
}

static inline int __deprecated CAENRFID_GetProtocol(caenrfid_handle_t *handle,
				caenrfid_protocol_t *protocol)
{
	return caenrfid_get_protocol(handle, (uint32_t *) protocol);
}

static inline int __deprecated CAENRFID_SetProtocol(caenrfid_handle_t *handle,
				caenrfid_protocol_t protocol)
{
	return caenrfid_set_protocol(handle, (uint32_t) protocol);
}

static inline int __deprecated CAENRFID_GetModulation(caenrfid_handle_t *handle,
				unsigned short *TxRx)
{
	return caenrfid_get_modulation(handle, (uint16_t *) TxRx);
}

static inline int __deprecated CAENRFID_SetModulation(caenrfid_handle_t *handle,
				unsigned short TxRxCfg)
{
	return caenrfid_set_modulation(handle, (uint16_t) TxRxCfg);
}

static inline int __deprecated CAENRFID_GetRFRegulation(caenrfid_handle_t *handle,
				unsigned short *RFRegulation)
{
	return caenrfid_get_regulation(handle, (uint16_t *) RFRegulation);
}

static inline int __deprecated CAENRFID_SetRFRegulation(caenrfid_handle_t *handle,
				unsigned short RFRegulation)
{
	return caenrfid_set_regulation(handle, (uint16_t) RFRegulation);
}

static inline int __deprecated CAENRFID_GetRFChannel(caenrfid_handle_t *handle,
				unsigned short *RFChannel)
{
	return caenrfid_get_rfchannel(handle, (uint16_t *) RFChannel);
}

static inline int __deprecated CAENRFID_SetRFChannel(caenrfid_handle_t *handle,
				unsigned short RFChannel)
{
	return caenrfid_set_rfchannel(handle, (uint16_t) RFChannel);
}

static inline int __deprecated CAENRFID_GetQ_C1G2(caenrfid_handle_t *handle,
				int *Q)
{
	return caenrfid_g2_get_q(handle, (uint16_t *) Q);
}

static inline int __deprecated CAENRFID_SetQ_C1G2(caenrfid_handle_t *handle,
				int Q)
{
	return caenrfid_g2_set_q(handle, (uint16_t) Q);
}

static inline int __deprecated CAENRFID_GetIODirection(caenrfid_handle_t *handle,
				unsigned int *IODirection)
{
	return caenrfid_get_io_direction(handle, IODirection);
}

static inline int __deprecated CAENRFID_SetIODirection(caenrfid_handle_t *handle,
				unsigned int IODirection)
{
	return caenrfid_set_io_direction(handle, IODirection);
}

static inline int __deprecated CAENRFID_GetIO(caenrfid_handle_t *handle,
				unsigned int *IORegister)
{
	return caenrfid_get_io(handle, IORegister);
}

static inline int __deprecated CAENRFID_GetSourceConfiguration(caenrfid_handle_t *handle,
				char *SourceName,
				CAENRFID_SOURCE_Parameter parameter,
				int *pvalue)
{
	return caenrfid_get_srcconf(handle, SourceName,
				parameter, (uint32_t *) pvalue);
}

static inline int __deprecated CAENRFID_SetSourceConfiguration(caenrfid_handle_t *handle,
				char *SourceName,
				CAENRFID_SOURCE_Parameter parameter,
				int pvalue)
{
	return caenrfid_set_srcconf(handle, *SourceName,
				parameter, (uint32_t) pvalue);
}

static inline int __deprecated CAENRFID_SetIO(caenrfid_handle_t *handle,
				unsigned int IORegister)
{
	return caenrfid_set_io(handle, IORegister);
}

static inline int __deprecated CAENRFID_Init(enum caenrfid_port port,
					char *addr,
					caenrfid_handle_t *handle)
{
        return caenrfid_open(port, addr, handle);
}

static inline int __deprecated CAENRFID_End(caenrfid_handle_t *handle)
{
        return caenrfid_close(handle);
}

#endif /* _CAENRFID_OLD_H */

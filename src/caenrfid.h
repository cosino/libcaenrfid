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

#ifndef _CAENRFID_H
#define _CAENRFID_H

#include <string.h>
#include <dlfcn.h>
#include <arpa/inet.h>

/*
 * Library's defines
 */

#define CAENRFID_ID_LEN			64
#define CAENRFID_SOURCE_NAME_LEN	30
#define CAENRFID_READPOINT_NAME_LEN	5

/*
 * Error codes
 */

enum caenrfid_error {
        CAENRFID_ERR_OK,		/* operation completed successfully */
        CAENRFID_ERR_TOO_MANY_CLIENTS,	/* to many clients open */
        CAENRFID_ERR_UNKNOW_PORT,	/* error on selected port */
        CAENRFID_ERR_WINSOCK,		/* can't open winsock 2.2 Library */
        CAENRFID_ERR_SOCKET,		/* can't open socket */
        CAENRFID_ERR_INVALID_HANDLE,	/* invalid handle */
        CAENRFID_ERR_OUT_OF_MEM,
        CAENRFID_ERR_COMMUNICATION,
        CAENRFID_ERR_TIMEOUT,
        CAENRFID_ERR_CHANNEL_EXIST,
        CAENRFID_ERR_GENERIC,
        CAENRFID_ERR_INVALID_PARAM,
        CAENRFID_ERR_READER_BUSY,
        CAENRFID_ERR_EOF,
	__CAENRFID_ERR_END
};

/*
 * Library's types
 */

enum caenrfid_port {
        CAENRFID_PORT_RS232,
        CAENRFID_PORT_RS485,
        CAENRFID_PORT_TCP,
        CAENRFID_PORT_USB,
	__CAENRFID_PORT_END
};

struct caenrfid_handle {
        enum caenrfid_port type;

        /* Per port type data */
        union {
                int serial;
                int tcp;
        };
};

enum caenrfid_protocol {
        CAENRFID_PROTOCOL_ISO18000_6B,
        CAENRFID_PROTOCOL_EPC_C1G1,
        CAENRFID_PROTOCOL_EM,
        CAENRFID_PROTOCOL_EPC_C1G2,
        CAENRFID_PROTOCOL_MULTIPROTOCOL,
        CAENRFID_PROTOCOL_EPC119,
	__CAENRFID_PROTOCOL_END
};

struct caenrfid_tag {
        uint8_t	id[CAENRFID_ID_LEN];
        size_t len;
        char source[CAENRFID_SOURCE_NAME_LEN];
        char readpoint[CAENRFID_READPOINT_NAME_LEN];
        enum caenrfid_protocol type;
        uint16_t rssi;
};

enum caenrfid_inv_flags {
	CAENRFID_INV_FLAG_RSSI = (1 << 0),
	__CAENRFID_INV_FLAG_END
};

enum caenrfid_src_param {
	CAENRFID_SRC_CFG_READCYCLE,
	CAENRFID_SRC_CFG_OBSERVEDTHRESHOLD,
	CAENRFID_SRC_CFG_LOSTTHRESHOLD,
	CAENRFID_SRC_CFG_G2_Q_VALUE,
	CAENRFID_SRC_CFG_G2_SESSION,
	CAENRFID_SRC_CFG_G2_TARGET,
	CAENRFID_SRC_CFG_G2_SELECTED,
	CAENRFID_SRC_CFG_ISO18006B_DESB,
	__CAENRFID_SRC_CFG
};

/*
 * Library's functions
 */

extern int caenrfid_get_fw_release(struct caenrfid_handle *handle, char *buf,
						size_t len);
extern int caenrfid_open(enum caenrfid_port port, char *addr,
					struct caenrfid_handle *handle);
extern int caenrfid_close(struct caenrfid_handle *handle);
extern int caenrfid_inventory(struct caenrfid_handle *handle,
			char *source, struct caenrfid_tag **tags, size_t *size);
extern int caenrfid_complex_inventory(struct caenrfid_handle *handle,
			char *source, uint8_t *mask, size_t mask_len,
			size_t position, enum caenrfid_inv_flags flags,
			struct caenrfid_tag **tags, size_t *size);
extern int caenrfid_add_readpoint(struct caenrfid_handle *handle,
				char *source, char *antenna);
extern int caenrfid_remove_readpoint(struct caenrfid_handle *handle,
				char *source, char *antenna);
extern int caenrfid_check_readpoint(struct caenrfid_handle *handle,
				char *source, char *antenna, uint16_t *val);
extern int caenrfid_g2_read_tag(struct caenrfid_handle *handle,
				struct caenrfid_tag *tag,
                                uint16_t bank, uint16_t addr, uint16_t len,
                                uint8_t *data, uint32_t pwd);
extern int caenrfid_g2_write_tag(struct caenrfid_handle *handle,
				struct caenrfid_tag *tag,
                                uint16_t bank, uint16_t addr, uint16_t len,
                                uint8_t *data, uint32_t pwd);
extern int caenrfid_g2_lock_tag(struct caenrfid_handle *handle,
				struct caenrfid_tag *tag,
				uint32_t payload, uint32_t pwd);
extern int caenrfid_g2_kill_tag(struct caenrfid_handle *handle,
				struct caenrfid_tag *tag, uint32_t pwd);
extern int caenrfid_get_power(struct caenrfid_handle *handle,
				uint32_t *pow);
extern int caenrfid_set_power(struct caenrfid_handle *handle,
				uint32_t pow);
extern int caenrfid_get_protocol(struct caenrfid_handle *handle,
				uint32_t *proto);
extern int caenrfid_set_protocol(struct caenrfid_handle *handle,
				uint32_t proto);
extern int caenrfid_get_modulation(struct caenrfid_handle *handle,
				uint16_t *mod);
extern int caenrfid_set_modulation(struct caenrfid_handle *handle,
				uint16_t mod);
extern int caenrfid_get_regulation(struct caenrfid_handle *handle,
				uint16_t *reg);
extern int caenrfid_set_regulation(struct caenrfid_handle *handle,
				uint16_t reg);
extern int caenrfid_get_rfchannel(struct caenrfid_handle *handle,
				uint16_t *ch);
extern int caenrfid_set_rfchannel(struct caenrfid_handle *handle,
				uint16_t ch);
extern int caenrfid_g2_get_q(struct caenrfid_handle *handle, uint16_t *q);
extern int caenrfid_g2_set_q(struct caenrfid_handle *handle, uint16_t q);
extern int caenrfid_get_io_direction(struct caenrfid_handle *handle,
				uint32_t *dir);
extern int caenrfid_set_io_direction(struct caenrfid_handle *handle,
				uint32_t dir);
extern int caenrfid_get_io(struct caenrfid_handle *handle,
				uint32_t *value);
extern int caenrfid_set_io(struct caenrfid_handle *handle,
				uint32_t value);
extern int caenrfid_get_srcconf(struct caenrfid_handle *handle,
				char *source, enum caenrfid_src_param param,
				uint32_t *value);
extern int caenrfid_set_srcconf(struct caenrfid_handle *handle,
				char *source, enum caenrfid_src_param param,
				uint32_t value);

#endif /* _CAENRFID_H */

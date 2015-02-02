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

#ifndef _CAENRFID_PROTO_H
#define _CAENRFID_PROTO_H

#define ANTENNA_STR_LEN         24
#define ANTENNA_MAX_PROTO       4
#define EPC_DATA_LEN            64
#define MAX_TAG_VALUE_LEN       132

/*
 * Inventory flags
 */

#define CAEN_RSSI_FLG		(1 << 0)
#define CAEN_FRAMED_FLG		(1 << 1)
#define CAEN_CONTINUOUS_FLG	(1 << 2)
#define CAEN_COMPACT_FLG	(1 << 3)

/*
 * Main CAENRFID message struct
 */

/* Message header */
struct proto_header {
	uint16_t ver;
	uint16_t id;
	uint32_t vendor;
	uint16_t len;
	uint8_t data[0];
} __packed;

/*
 * Known vendors
 */

#define CAENRFID_VENDOR		21336

/*
 * Commands definition
 */

#define CMD_NEWRAWREADID	0x13
#define CMD_ADDREADPOINT	0x5f
#define CMD_REMREADPOINT	0x60
#define CMD_SETPOWER		0x64
#define CMD_SETMODULATION	0x72
#define CMD_GETPOWER		0x73
#define CMD_CHANGEPROTOCOL	0x74
#define CMD_CHECKANTENNA	0x76
#define CMD_CHECKRPINSRC	0x78
#define CMD_GETPROTOCOL		0x79
#define CMD_GETFWRELEASE	0x7c
#define CMD_GETMODULATION	0x81
#define CMD_GETIO		0x86
#define CMD_SETIO		0x87
#define CMD_SETIODIR		0x88
#define CMD_GETIODIR		0x89
#define CMD_SETSRCCONF		0x8a
#define CMD_GETSRCCONF		0x8b
#define CMD_GETEVENTMODE	0x92
#define CMD_G2PROGRAMID		0x95
#define CMD_G2READ		0x96
#define CMD_G2WRITE		0x97
#define CMD_G2LOCK		0x98
#define CMD_G2KILL		0x99
#define CMD_G2SETQ		0x9b
#define CMD_G2GETQ		0x9c
#define CMD_GETRDRINFO		0x9e
#define CMD_SETLBTMODE		0x9f
#define CMD_GETLBTMODE		0xa0
#define CMD_SETRFREGULATION	0xa1
#define CMD_GETRFREGULATION	0xa2
#define CMD_SETRFCHANNEL	0xa3
#define CMD_GETRFCHANNEL	0xa4

#define CMD_DUMPREGS		0xf0

/*
 * Logical sources configuration parameters
 */

#define LSC_READCYCLES		0
#define LSC_OBSTHR		1
#define LSC_LOSTTHR		2
#define LSC_G2Q			3
#define LSC_G2SESSION		4
#define LSC_G2TARGET		5
#define LSC_G2SELECTED		6
#define LSC_ISOBDESB		7

/*
 * Error codes
 */

#define ERR_SUCCESS		0
#define ERR_GENERIC		-1	/* From: ISO18000-6B AND EPC1G2 */
#define ERR_TIMEOUT		-2
#define ERR_TTYSWITCH		-3
#define ERR_LOCKED		-4	/* From: ISO18000-6B AND EPC1G2 */
#define ERR_UPGREQ		-5
#define ERR_UNSUPPORTED		-6	/* From: EPC1G2 */
#define ERR_POWER		-7	/* From: EPC1G2 */
#define ERR_NONSPECIFIC		-8	/* From: EPC1G2 */
#define ERR_OOBCMD		-9	/* Ver. 2.3 */

/* 
 * Modulation
 */

#define DELIMITER1		(0 << 10)
#define DELIMITER2		(1 << 10)
#define DELIMITER3		(2 << 10)
#define DELIMITER4		(3 << 10)
#define MOD40KBIT		(0 << 12)
#define MOD10KBIT		(1 << 12)
#define TX40KBIT		(0 << 8)
#define TX20KBIT		(1 << 8)
#define TX10KBIT		(2 << 8)
#define TX5KBIT			(3 << 8)
#define RX160KBIT		(0 << 0)
#define RX80KBIT		(1 << 0)
#define RX40KBIT		(2 << 0)
#define RX20KBIT		(3 << 0)
#define RX10KBIT		(4 << 0)
#define RX5KBIT			(5 << 0)

/* Possible configurations defined by ISO18000 */
#define TX10RX10		(MOD10KBIT | DELIMITER1 | TX10KBIT | RX10KBIT)
#define TX10RX40		(MOD10KBIT | DELIMITER4 | TX10KBIT | RX40KBIT)
#define TX40RX40		(MOD40KBIT | DELIMITER1 | TX40KBIT | RX40KBIT)
#define TX40RX160		(MOD40KBIT | DELIMITER4 | TX40KBIT | RX160KBIT)

#endif /* _CAENRFID_PROTO_H */

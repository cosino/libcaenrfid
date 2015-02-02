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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <msgbuff.h>
#include <avp.h>

#include "logging.h"
#include "macros.h"
#include "caenrfid_proto.h"
#include "caenrfid.h"

/* FIXME: this should/can be configurable */
unsigned int timeout = 10000;	/* ms */

/*
 * Private functions
 */

static struct msgbuff *alloc_buff(void) {
        struct msgbuff *sbuff;

        sbuff = msgbuff_alloc(PAGE_SIZE);
        EXIT_ON(!sbuff);
	
        sbuff->id = 0;		/* FIXME: should change? */

        return sbuff;
}

static int caenrfid_send_message(struct msgbuff *buff)
{
        struct proto_header *h;
	int len, ret;

        h = msgbuff_push_head(buff, sizeof(*h));
	EXIT_ON(!h);

        len = msgbuff_len(buff);

        h->ver = htobe16(0x8001);
        h->id = htobe16(buff->id);
        h->vendor = htobe32(CAENRFID_VENDOR);
        h->len = htobe16(len);

	ret = sendn(buff->fd, h, len, timeout);
	msgbuff_free(buff);

	return ret;
}

static struct msgbuff *caenrfid_recv_message(int fd)
{
        struct msgbuff *buff;
        struct proto_header *m, h;
        char *ptr = (char *) &h;
        int len, ret = 0;

        errno = 0;

        /*
         * Try to read the message's header first.
         */

        ret = recvn(fd, &h, sizeof(h), timeout);
        if (ret <= 0) {
                dbg("unable to read client's message");
                goto exit;
        }

        if (!strncmp(ptr, "@#UpGrEq#@", 10)) {
                dbg("UpGrEq error");
                goto exit;
        }

        if (!strncmp(ptr, "$%OoBcMd%$", 10)) { /* ver. 2.3 - Out-Of-Band cmds */
                dbg("OoBcMd error");
                goto exit;
        }

        /* Little sanity checks */
        if (be16toh(h.ver) != 0x0001) {
                dbg("unsupported protocol version!");
                goto exit;
        }
        if (be32toh(h.vendor) != CAENRFID_VENDOR) {
                dbg("invalid vendor!");
                goto exit;
        }

        /*
         * Then try to read the message's body and put all into a msgbuff.
         */

        len = be16toh(h.len) - sizeof(h);

        buff = msgbuff_alloc(len);
        EXIT_ON(!buff);

        /* Then try to read the following data */
        m = msgbuff_push_head(buff, sizeof(*m));
        BUG_ON(!m);
        *m = h;

        ptr = msgbuff_push_tail(buff, len);
        BUG_ON(!ptr);
        if (len) {
                ret = recvn(fd, ptr, len, timeout);
                if (ret <= 0)
                        goto free_buff;
        }

        /* In the end fill the data part */
        buff->fd = fd;
        buff->id = be16toh(m->id);

        return buff;

free_buff:
        msgbuff_free(buff);
exit:
        return NULL;
}

static struct msgbuff *send_receive_data(struct caenrfid_handle *handle,
						struct msgbuff *sbuff)
{
	struct msgbuff *rbuff;
	int fd, ret;

	switch (handle->type) {
	case CAENRFID_PORT_TCP:
		sbuff->fd = fd = handle->tcp;
		break;

	case CAENRFID_PORT_RS232:
		sbuff->fd = fd = handle->serial;
		break;

	default:
		return NULL;
	}

	ret = caenrfid_send_message(sbuff);
	if (ret < 0)
		return NULL;

	rbuff = caenrfid_recv_message(fd);
	if (!rbuff)
		return NULL;

	/* Drop the message header */
	msgbuff_pull_head(rbuff, sizeof(struct proto_header));

	return rbuff;
}

/*
 * Exported functions
 */

int caenrfid_complex_inventory(struct caenrfid_handle *handle, char *source,
				uint8_t *mask, size_t mask_len, size_t position,
				enum caenrfid_inv_flags flags,
				struct caenrfid_tag **tags, size_t *size)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code, tmp;
	uint32_t secs, u_secs;
	size_t len;
	int ret;

	sbuff = alloc_buff();

	/* Sanity checks */
	if (mask_len > 0 && !mask)
		return -EINVAL;

	avp_add_cmd(sbuff, CMD_NEWRAWREADID);

	if (source)
		avp_add_source_name(sbuff, source, strlen(source) + 1);

	if (mask_len > 0 || flags != 0) {
		avp_add_length(sbuff, mask_len);
		avp_add_tag_id(sbuff, mask, mask_len);
		avp_add_tag_address(sbuff, position);
	}
	if (flags != 0)
		avp_add_bitmask(sbuff, flags);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_NEWRAWREADID) {
		ret = -EINVAL;
		goto exit;
	}

	*tags = NULL;
	*size = 0;
	while (1) {
		*tags = realloc(*tags, sizeof(struct caenrfid_tag) * (*size + 1));
		if (!*tags)
			break;

		ret = avp_manage_source_name(rbuff,
					(*tags)[*size].source);
		if (ret < 0)
			break;

		ret = avp_manage_readpoint_name(rbuff,
					(*tags)[*size].readpoint);
		if (ret < 0)
			break;

		ret = avp_manage_timestamp(rbuff, &secs, &u_secs);
		if (ret < 0)
			break;

		ret = avp_manage_tag_type(rbuff, &tmp);
		if (ret < 0)
			break;
		(*tags)[*size].type = tmp;

		ret = avp_manage_tag_id_len(rbuff, &tmp);
		if (ret < 0)
			break;
		(*tags)[*size].len = tmp;

		ret = avp_manage_tag_id(rbuff, (*tags)[*size].id, &len);
		if (ret < 0)
			break;

		ret = avp_manage_rssi(rbuff, &(*tags)[*size].rssi);
		if (ret < 0) {
			/* this is not an error */
			(*tags)[*size].rssi = 0;
		}

		(*size)++;
	}

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_inventory(struct caenrfid_handle *handle, char *source,
				struct caenrfid_tag **tags, size_t *size)
{
	return caenrfid_complex_inventory(handle, source,
						NULL, 0, 0, 0,
						tags, size);
}

int caenrfid_add_readpoint(struct caenrfid_handle *handle,
					char *source, char *antenna)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_ADDREADPOINT);
	avp_add_source_name(sbuff, source, strlen(source) + 1);
	avp_add_readpoint_name(sbuff, antenna, strlen(antenna) + 1);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_ADDREADPOINT) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_remove_readpoint(struct caenrfid_handle *handle,
					char *source, char *antenna)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_REMREADPOINT);
	avp_add_source_name(sbuff, source, strlen(source) + 1);
	avp_add_readpoint_name(sbuff, antenna, strlen(antenna) + 1);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_REMREADPOINT) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_check_readpoint(struct caenrfid_handle *handle,
				char *source, char *antenna, uint16_t *val)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_CHECKRPINSRC);
	avp_add_readpoint_name(sbuff, antenna, strlen(antenna) + 1);
	avp_add_source_name(sbuff, source, strlen(source) + 1);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_CHECKRPINSRC) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_boolean(rbuff, val);
	if (ret < 0)
		ret = 0;	/* no boolean AVP... */

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_get_power(struct caenrfid_handle *handle, uint32_t *pow)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_GETPOWER);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_GETPOWER) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_power_value_client(rbuff, pow);
	if (ret < 0)
		ret = 0;	/* no power AVP... */

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_set_power(struct caenrfid_handle *handle, uint32_t pow)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_SETPOWER);
	avp_add_power_value_client(sbuff, pow);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_SETPOWER) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_get_protocol(struct caenrfid_handle *handle, uint32_t *proto)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_GETPROTOCOL);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_GETPROTOCOL) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_protocol(rbuff, proto);
	if (ret < 0)
		ret = 0;	/* no protocol AVP... */

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_set_protocol(struct caenrfid_handle *handle, uint32_t proto)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_CHANGEPROTOCOL);
	avp_add_protocol(sbuff, proto);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_CHANGEPROTOCOL) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_get_fw_release(struct caenrfid_handle *handle, char *buf, size_t len)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_GETFWRELEASE);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_GETFWRELEASE) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_fw_release(rbuff, buf, len);
	if (ret < 0)
		goto exit;

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_get_modulation(struct caenrfid_handle *handle, uint16_t *mod)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_GETMODULATION);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_GETMODULATION) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_modulation(rbuff, mod);
	if (ret < 0)
		ret = 0;	/* no modulation AVP... */

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_set_modulation(struct caenrfid_handle *handle, uint16_t mod)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_SETMODULATION);
	avp_add_modulation(sbuff, mod);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_SETMODULATION) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_g2_read_tag(struct caenrfid_handle *handle,
				struct caenrfid_tag *tag,
				uint16_t bank, uint16_t addr, uint16_t len,
				uint8_t *data, uint32_t pwd)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_G2READ);
	avp_add_source_name(sbuff,
			tag->source, strlen(tag->source) + 1);
	avp_add_tag_id_len(sbuff, tag->len);
	avp_add_tag_id(sbuff, tag->id, tag->len);
	avp_add_membank(sbuff, bank);
	avp_add_tag_address(sbuff, addr);
	avp_add_length(sbuff, len);
	if (pwd)
		avp_add_g2_password(sbuff, pwd);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_G2READ) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_tag_value(rbuff, data);
	if (ret < 0)
		goto exit;

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_g2_write_tag(struct caenrfid_handle *handle,
				struct caenrfid_tag *tag,
				uint16_t bank, uint16_t addr, uint16_t len,
				uint8_t *data, uint32_t pwd)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_G2WRITE);
	avp_add_source_name(sbuff,
			tag->source, strlen(tag->source) + 1);
	avp_add_tag_id_len(sbuff, tag->len);
	avp_add_tag_id(sbuff, tag->id, tag->len);
	avp_add_membank(sbuff, bank);
	avp_add_tag_address(sbuff, addr);
	avp_add_length(sbuff, len);
	avp_add_tag_value(sbuff, data, len);
	if (pwd)
		avp_add_g2_password(sbuff, pwd);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_G2WRITE) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_g2_lock_tag(struct caenrfid_handle *handle,
				struct caenrfid_tag *tag,
				uint32_t payload, uint32_t pwd)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_G2LOCK);
	avp_add_source_name(sbuff,
			tag->source, strlen(tag->source) + 1);
	avp_add_tag_id_len(sbuff, tag->len);
	avp_add_tag_id(sbuff, tag->id, tag->len);
	avp_add_g2_payload(sbuff, payload);
	if (pwd)
		avp_add_g2_password(sbuff, pwd);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_G2LOCK) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_g2_kill_tag(struct caenrfid_handle *handle,
				struct caenrfid_tag *tag, uint32_t pwd)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_G2KILL);
	avp_add_source_name(sbuff,
			tag->source, strlen(tag->source) + 1);
	avp_add_tag_id_len(sbuff, tag->len);
	avp_add_tag_id(sbuff, tag->id, tag->len);
	if (pwd)
		avp_add_g2_password(sbuff, pwd);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_G2KILL) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_get_regulation(struct caenrfid_handle *handle, uint16_t *reg)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_GETRFREGULATION);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_GETRFREGULATION) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_regulation(rbuff, reg);
	if (ret < 0)
		ret = 0;	/* no regulation AVP... */

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_set_regulation(struct caenrfid_handle *handle, uint16_t reg)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_SETRFREGULATION);
	avp_add_regulation(sbuff, reg);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_SETRFREGULATION) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_get_rfchannel(struct caenrfid_handle *handle, uint16_t *ch)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_GETRFCHANNEL);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_GETRFCHANNEL) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_rfchannel(rbuff, ch);
	if (ret < 0)
		ret = 0;	/* no rfchannel AVP... */

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_set_rfchannel(struct caenrfid_handle *handle, uint16_t ch)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_SETRFCHANNEL);
	avp_add_rfchannel(sbuff, ch);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_SETRFCHANNEL) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_g2_get_q(struct caenrfid_handle *handle, uint16_t *q)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_G2GETQ);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_G2GETQ) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_q_value(rbuff, q);
	if (ret < 0)
		ret = 0;	/* no Q value AVP... */

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_g2_set_q(struct caenrfid_handle *handle, uint16_t q)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_G2SETQ);
	avp_add_q_value(sbuff, q);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_G2SETQ) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_get_io_direction(struct caenrfid_handle *handle, uint32_t *dir)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_GETIODIR);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_GETIODIR) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_io_register(rbuff, dir);
	if (ret < 0)
		ret = 0;

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_set_io_direction(struct caenrfid_handle *handle, uint32_t dir)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_SETIODIR);
	avp_add_io_register(sbuff, dir);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_SETIODIR) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_get_io(struct caenrfid_handle *handle, uint32_t *value)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_GETIO);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_GETIO) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_io_register(rbuff, value);
	if (ret < 0)
		ret = 0;

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_set_io(struct caenrfid_handle *handle, uint32_t value)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_SETIO);
	avp_add_io_register(sbuff, value);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_SETIO) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_get_srcconf(struct caenrfid_handle *handle,
				char *source, enum caenrfid_src_param param,
				uint32_t *value)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_GETSRCCONF);
	avp_add_source_name(sbuff, source, strlen(source) + 1);
	avp_add_src_conf_parameter(sbuff, param);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_GETSRCCONF) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_src_conf_value(rbuff, value);
	if (ret < 0)
		ret = 0;

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_set_srcconf(struct caenrfid_handle *handle,
				char *source, enum caenrfid_src_param param,
				uint32_t value)
{
	struct msgbuff *sbuff, *rbuff;
	uint16_t cmd, code;
	int ret;

	sbuff = alloc_buff();

	avp_add_cmd(sbuff, CMD_SETSRCCONF);
	avp_add_source_name(sbuff, source, strlen(source) + 1);
	avp_add_src_conf_parameter(sbuff, param);
	avp_add_src_conf_value(sbuff, value);

	rbuff = send_receive_data(handle, sbuff);
	if (!rbuff) {
		dbg("unable to send/receive command");
		ret = -EIO;
		goto exit;
	}

	ret = avp_manage_command(rbuff, &cmd);
	if (ret < 0)
		goto exit;
	if (cmd != CMD_SETSRCCONF) {
		ret = -EINVAL;
		goto exit;
	}

	ret = avp_manage_result_code(rbuff, &code);
	if (ret < 0)
		goto exit;

	ret = code;

exit:
	msgbuff_free(rbuff);

	return ret;
}

int caenrfid_open(enum caenrfid_port port, char *addr,
					struct caenrfid_handle *handle)
{
	char *dup, *colon, *comma;
	int ipport, rate;
	int ret;

	dbg("%s", __func__);

	if (!handle)
		return -CAENRFID_ERR_INVALID_HANDLE;

	/* Now we must duplicate "addr" string in order to be able to
	 * modify it!
	 * By using strdupa() we can forget using free()! ;)
	 */
	dup = strdupa(addr);
	if (!dup)
		return -CAENRFID_ERR_OUT_OF_MEM;

	/* Do The-Right-Thing(TM) according to port type */
	switch (port) {
	case CAENRFID_PORT_TCP: {
		/* In this case we parse address[:port], where
		 *    address:	is a TCP/IP hostname or IP address
		 *    port:	is the port to be used (defualt is 1000)
		 */
		dbg("%s: TCP: %s", __func__, dup);
		handle->type = CAENRFID_PORT_TCP;

		/* Parse the "addr" parameter */
		colon = strchr(dup, ':');
		if (colon) {
			ret = sscanf(colon + 1, "%d", &ipport);
			if (ret < 1 || ipport < 1 || ipport > 65535)
				return -CAENRFID_ERR_INVALID_PARAM;
			*colon = '\0';
		} else
			ipport = 1000;

		ret = socket_open(dup, ipport, &handle->tcp);
		if (ret < 0) {
			dbg("unable TCP port");
			return -CAENRFID_ERR_UNKNOW_PORT;
		}
		
		break;
	}

	case CAENRFID_PORT_RS232: {
		/* In this case we parse port[,baud], where
		 *    port:	is a serial port name
		 *    baud:	is the baud rate (default 115200)
		 */
		dbg("%s: RS232: %s", __func__, dup);
		handle->type = CAENRFID_PORT_RS232;

		/* Parse the "addr" parameter */
		comma = strchr(dup, ',');
		if (comma) {
			ret = sscanf(comma + 1, "%d", &rate);
			if (ret < 1 || rate < 1 || rate > 230400)
				return -CAENRFID_ERR_INVALID_PARAM;
			*comma = '\0';
		} else
			rate = 115200;

		ret = serial_open(dup, rate, &handle->serial);
		if (ret < 0) {
			dbg("unable to open RS232 port");
			return -CAENRFID_ERR_UNKNOW_PORT;
		}
		
		break;
	}

	default:
		dbg("%s: unknow port type", __func__);

		return -CAENRFID_ERR_UNKNOW_PORT;
	}

	return CAENRFID_ERR_OK;
}

int caenrfid_close(struct caenrfid_handle *handle)
{
	int ret;

	dbg("%s", __func__);

	if (!handle)
		return -CAENRFID_ERR_INVALID_HANDLE;

	/* Do The-Right-Thing(TM) according to port type */
	switch (handle->type) {
	case CAENRFID_PORT_TCP:
		ret = socket_close(handle->tcp);
		if (ret < 0)
			return -CAENRFID_ERR_UNKNOW_PORT;

		break;

	case CAENRFID_PORT_RS232:
		ret = serial_close(handle->serial);
		if (ret < 0)
			return -CAENRFID_ERR_UNKNOW_PORT;

		break;

	default:
		dbg("%s: unknow port type", __func__);
	}

	return CAENRFID_ERR_OK;
}

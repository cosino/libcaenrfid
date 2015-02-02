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

#ifndef _LINUX_GNU_H
#define _LINUX_GNU_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <arpa/inet.h>

/* Conversion interfaces.  */
# include <bits/byteswap.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define htobe16(x) __bswap_16 (x)
#define htole16(x) (x)
#define be16toh(x) __bswap_16 (x)
#define le16toh(x) (x)

#define htobe32(x) __bswap_32 (x)
#define htole32(x) (x)
#define be32toh(x) __bswap_32 (x)
#define le32toh(x) (x)

#define htobe64(x) __bswap_64 (x)
#define htole64(x) (x)
#define be64toh(x) __bswap_64 (x)
#define le64toh(x) (x)

#else

#define htobe16(x) (x)
#define htole16(x) __bswap_16 (x)
#define be16toh(x) (x)
#define le16toh(x) __bswap_16 (x)

#define htobe32(x) (x)
#define htole32(x) __bswap_32 (x)
#define be32toh(x) (x)
#define le32toh(x) __bswap_32 (x)

#define htobe64(x) (x)
#define htole64(x) __bswap_64 (x)
#define be64toh(x) (x)
#define le64toh(x) __bswap_64 (x)
#endif /* __BYTE_ORDER == __LITTLE_ENDIAN */

/*
 * Global system dependent types
 */

struct tcp_data {
	int socket;
};

/*
 * Global system dependent defines
 */

extern int socket_open_listen(unsigned short port, int *s_listen);
extern int socket_accept_connection(int s_listen, int *s_accept);
extern int socket_open(const char *addr, unsigned short port, int *s_connect);
extern int socket_close(int s);

extern int serial_open(const char *port, unsigned int rate, int *s_connect);
extern int serial_close(int s);

extern int wait_for_data(int fd);
extern int recvn(int s, void *vptr, size_t n, unsigned int to);
extern int sendn(int s, void *vptr, size_t n, unsigned int to);
#endif /* _LINUX_GNU_H */

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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include "macros.h"
#include "logging.h"
#include "linux-gnu.h"

/*
 * Local functions
 */

static int readn(int fd, void *vptr, size_t n)
{
	int nleft = n, nread;
	char *ptr = vptr;

	while (nleft > 0) {
		nread = read(fd, ptr, nleft);
		if (nread < 0) {
			if (errno != EAGAIN)
				return -1;
			nread = 0;
		} else if (nread == 0)
			break;

		nleft -= nread;
		ptr += nread;
	}

	return n - nleft;
}

static int writen(int fd, void *vptr, size_t n)
{
	int nleft = n, nwritten;
	char *ptr = vptr;

	while (nleft > 0) {
		nwritten = write(fd, ptr, nleft);
		if (nwritten < 0) {
			if (errno != EAGAIN)
				return -1;
			nwritten = 0;
		} else if (nwritten == 0)
			break;

		nleft -= nwritten;
		ptr += nwritten;
	}

	return n - nleft;
}

/*
 * Exported functions
 */

int socket_open_listen(unsigned short port, int *s_listen)
{
	struct sockaddr_in channel;
	int on = 1;
	int ret;

	memset(&channel, 0, sizeof(channel));	// zerochannel 
	channel.sin_family = AF_INET;
	channel.sin_addr.s_addr = htonl(INADDR_ANY);
	channel.sin_port = htons(port);

	ret = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ret < 0) {
		err("socket error");
		return -1;
	}
	*s_listen = ret;

	setsockopt(*s_listen, SOL_SOCKET, SO_REUSEADDR,
					(char *) &on, sizeof(on));

	ret = bind(*s_listen, (struct sockaddr *) &channel, sizeof(channel));
	if (ret < 0) {
		err("bind error");
		return -1;
	}

	ret = listen(*s_listen, 10);
	if (ret < 0) {
		err("listen error");
		return -1;
	}

	return 0;
}

int socket_accept_connection(int s_listen, int *s_accept)
{
	struct sockaddr_in sock_addr;
	socklen_t sock_addr_len = sizeof(sock_addr);
	int ret;

	ret = accept(s_listen, (struct sockaddr *) &sock_addr, &sock_addr_len);
	if (ret < 0)
		return -1;
	*s_accept = ret;

	dbg("connection accepted");

	return 0;
}

int socket_open(const char *addr, unsigned short port, int *s_connect)
{
        struct hostent *host_ent;
        struct sockaddr_in sock_addr;
        int s, ret;

        host_ent = gethostbyname(addr);
        if (!host_ent) {
                dbg("unable to resolve server name %s\n", addr);
                return -1;
        }

        bzero((void *) &sock_addr, sizeof(sock_addr));
        sock_addr.sin_family = AF_INET;
        sock_addr.sin_addr.s_addr =
                        ((struct in_addr *) host_ent->h_addr)->s_addr;
        sock_addr.sin_port = htons(port);

        ret = socket(AF_INET, SOCK_STREAM, 0);
        if (ret < 0) {
                dbg("unable to create connection socket\n");
                return -1;
        }
        s = ret;

        ret = connect(s, (struct sockaddr *) &sock_addr, sizeof(sock_addr));
        if (ret < 0) {
                dbg("unable to connect server\n");
                return -1;
        }

        *s_connect = s;

        return 0;
}

int socket_close(int s)
{
	return close(s);
}

int serial_open(const char *port, unsigned int rate, int *s_connect)
{
	struct termios term;
	int fd;
	int ret;

	/* Sanity checks */
	switch (rate) {
	case 115200 :
		rate = B115200;
		break;

	default :   /* error */
		dbg("invalid baud rate");
		return -1;
	}

	ret = open(port, O_RDWR | O_NOCTTY);
	if (ret == -1) {
		dbg("unable to open %s (%m)", name);
		return -1;
	}
	fd = ret;

	ret = tcgetattr(fd, &term);
	if (ret < 0) {
		dbg("unable to get term attribute");
		return -1;
	}

	cfmakeraw(&term);

	ret = cfsetispeed(&term, rate);
	if (ret < 0) {
		dbg("unable to set input speed");
		return -1;
	}
	ret = cfsetospeed(&term, rate);
	if (ret < 0) {
		dbg("unable to set output speed");
		return -1;
	}
	dbg("using baud rate %d", rate);

	cfmakeraw(&term);
	term.c_cc[VTIME] = 0;
	term.c_cc[VMIN] = 1;
	ret = tcsetattr(fd, TCSANOW, &term);
	if (ret < 0) {
		dbg("unable to set attribute");
		return -1;
	}

        *s_connect = fd;

        return 0;
}

int serial_close(int s)
{
	return close(s);
}

int wait_for_data(int fd)
{
	fd_set read;

	FD_ZERO(&read);
	FD_SET(fd, &read);

	return select(fd + 1, &read, NULL, NULL, NULL);
}

int recvn(int fd, void *vptr, size_t n, unsigned int to)
{
	return readn(fd, vptr, n);
}

int sendn(int fd, void *vptr, size_t n, unsigned int to)
{
	return writen(fd, vptr, n);
}

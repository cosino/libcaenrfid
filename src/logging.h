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

#ifndef _LOGGING_H
#define _LOGGING_H

#include <stdio.h>
#include <syslog.h>

#ifdef ENABLE_DEBUG
#define __message(level, fmt, args...)				\
		fprintf(stderr, "%s[%4d]: " fmt "\n" ,		\
			__FILE__, __LINE__ , ## args)

#define __dbg(fmt, args...)                                             \
        do {                                                            \
		__message(LOG_DEBUG, fmt , ## args);			\
        } while (0)

#define DUMP(code)                                                      \
        do {                                                            \
		code							\
        } while (0)

#else  /* !ENABLE_DEBUG */

#define __message(level, fmt, args...)                          \
                fprintf(stderr, fmt "\n" , ## args)

#define __dbg(fmt, args...)                                             \
                                /* do nothing! */

#define DUMP(code)                                                      \
                                /* do nothing! */
#endif /* ENABLE_DEBUG */

#define __info(fmt, args...)                                            \
                __message(LOG_INFO, fmt , ## args)

#define __err(fmt, args...)                                             \
                __message(LOG_ERR, fmt , ## args)

/*
 * Exported defines
 *
 * The following defines should be preferred to the above one into
 * normal code.
 */

#ifdef ENABLE_DEBUG
#define info(fmt, args...)                                              \
                __info("%s: " fmt , __func__ , ## args)
#define err(fmt, args...)                                               \
                __err("%s: " fmt , __func__ , ## args)
#define dbg(fmt, args...)                                               \
                __dbg("%s: " fmt , __func__ , ## args)

#else  /* ENABLE_DEBUG */

#define info(args...)           __info(args)
#define err(args...)            __err(args)
#define dbg(args...)            __dbg(args)

#endif /* !ENABLE_DEBUG */

#endif /* _LOGGING_H */

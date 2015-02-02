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

#ifndef _MACROS_H
#define _MACROS_H

#include <dlfcn.h>

#define __packed		__attribute__ ((packed))
#define __constructor		__attribute__ ((constructor))

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define container_of(ptr, type, member)				 \
	({							      \
		const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
		(type *)( (char *)__mptr - offsetof(type,member) );     \
	})

#define BUILD_BUG_ON_ZERO(e)					    \
		(sizeof(char[1 - 2 * !!(e)]) - 1)
#define __must_be_array(a)					      \
		BUILD_BUG_ON_ZERO(__builtin_types_compatible_p(typeof(a), \
							typeof(&a[0])))
#define ARRAY_SIZE(arr)						 \
		(sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))

#define unlikely(x)	     __builtin_expect(!!(x), 0)
#define BUG()                                                           \
        do {                                                            \
                Dl_info info;                                           \
                dladdr(__builtin_return_address(0), &info);             \
                err("fatal error in %s() from %s()",                    \
                                __func__, info.dli_sname);              \
                exit(EXIT_FAILURE);                                     \
        } while (0)
#define EXIT_ON(condition)					      \
	do {							    \
		if (unlikely(condition))				\
			BUG();					  \
	} while(0)
#define BUG_ON(condition)       EXIT_ON(condition)

#endif /* _MACROS_H */

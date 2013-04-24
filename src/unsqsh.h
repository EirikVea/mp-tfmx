#ifndef _UNSQSH_H_
#define _UNSQSH_H_

#include "MyEndian.h"

udword tfmx_sqsh_get_ulen (ubyte *src, udword srclen);
void tfmx_sqsh_unpack(ubyte *src, ubyte *dst, sdword dstlen);

#endif // _UNSQSH_H_

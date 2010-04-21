/* WinKexec: kexec for Windows
 * Copyright (C) 2008-2009 John Stumpo
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* Bare-bones subset of the C standard library for use by the kernel
 * reassembly and verification code.  */

#include "console.h"
#include "stdlib.h"
#include "string.h"
#include "../util.h"

void KEXEC_NORETURN abort(void)
{
  putstr("abort() was called!\n");
  util_int3();
  util_hlt();
}


/* Not quicksort (in the interest of stack space) but insertion sort.
   Sure, it's O(n^2) in time, but we're not going to be sorting huge
   lists with it.  */
void qsort(void* base, size_t num, size_t size,
  int(*compare)(const void*, const void*))
{
  size_t pos1;
  size_t pos2;
  unsigned char buf[32];

  if (size > 32) {
    putstr("qsort: Maximum element size exceeded\n");
    abort();
  }

  for (pos1 = 1; pos1 < num; pos1++) {
    for (pos2 = pos1;
         compare(base + ((pos2 - 1) * size),
                 base + ( pos2      * size)) > 0 && pos2 > 0;
         pos2--)
    {
      memcpy(buf, base + ((pos2 - 1) * size), size);
      memcpy(base + ((pos2 - 1) * size), base + (pos2 * size), size);
      memcpy(base + (pos2 * size), buf, size);
    }
  }
}


/* TODO: Rewrite mem* in assembly. */
int memcmp(const void* a, const void* b, size_t len)
{
  const unsigned char* c = a;
  const unsigned char* d = b;
  size_t i;

  for (i = 0; i < len; i++)
    if (c[i] != d[i])
      return c[i] - d[i];

  return 0;
}


void* memmove(void* dest, const void* src, size_t len)
{
  const unsigned char* a = src;
  unsigned char* b = dest;
  size_t i;

  if (b < a) {
    for (i = 0; i < len; i++)
      b[i] = a[i];
  } else {
    for (i = len; i > 0; i--)
      b[i-1] = a[i-1];
  }

  return dest;
}

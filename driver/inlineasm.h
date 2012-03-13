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

/* Various utility functions written in assembly for use by the final bit
 * of C code to set things up for the Linux boot.  */

#ifndef KEXEC_DRIVER_INLINEASM_H
#define KEXEC_DRIVER_INLINEASM_H

#include <stdint.h>

/* Disable interrupts. */
static void cli(void);
/* Repeatedly halt the processor in a never-ending loop. */
static void cli_hlt(void) KEXEC_NORETURN;

/* Figure out whether PAE is enabled.
   Returns 1 if true or 0 if false.  */
static int pae_enabled(void);
/* Get cr3, which is the physical address of the page directory. */
static uint32_t get_cr3(void);
/* Flush from the TLB the page whose address is passed as arg1. */
static void invlpg(const void* page_address);
/* Get the current processor number.
 * The MinGW folks did finally unbreak KeGetCurrentProcessorNumber(),
 * but it requires linking in libmingwex.a, which for kernel mode
 * software just really doesn't feel right. */
static uint32_t current_processor(void);
/* A convenient debug breakpoint. */
static void int3(void);
/* Reload cr3 with the same value it had before.
   Useful to force a PDPT reload or forget any cached mappings.  */
static void reload_cr3(void);

#ifdef __GNUC__

static inline void cli(void)
{
  __asm__ __volatile__ ("cli");
}

static inline void KEXEC_NORETURN cli_hlt(void)
{
  cli();
  while (1)
    __asm__ __volatile__ ("hlt");
}

static inline int pae_enabled(void)
{
  uint32_t cr4;
  __asm__ __volatile__ ("movl %%cr4, %0" : "=r" (cr4));
  return !!(cr4 & 0x00000020);
}

static inline uint32_t get_cr3(void)
{
  uint32_t cr3;
  __asm__ __volatile__ ("movl %%cr3, %0" : "=r" (cr3));
  return cr3;
}

static inline void invlpg(const void* pg)
{
  __asm__ __volatile__ ("invlpg (%0)" : : "r" (pg) : "memory");
}

static inline uint32_t current_processor(void)
{
  extern uint8_t current_processor_number __asm__("%fs:0x51");
  return current_processor_number;
}

static inline void int3(void)
{
  __asm__ __volatile__ ("int3");
}

static inline void reload_cr3(void)
{
  uint32_t cr3;
  __asm__ __volatile__ ("movl %%cr3, %0\n\t"
                        "movl %0, %%cr3"
                        : "=r" (cr3) : : "memory");
}

#else
#error "Please port the inline assembly functions in inlineasm.h to your compiler's syntax."
#endif

#endif

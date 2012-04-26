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

#define CR3_ADDR_MASK 0xfffff000
#define CR3_ADDR_MASK_PAE 0xffffffe0

#define CR4_PAE 0x00000020

#define PTE_PRESENT 0x00000001
#define PTE_RW 0x00000002
#define PTE_NX 0x8000000000000000ULL

#define PTE_ADDR_MASK 0xfffff000
#define PTE_ADDR_MASK_PAE 0x7ffffffffffff000

/* Disable interrupts. */
static void cli(void);
/* Repeatedly halt the processor in a never-ending loop. */
static void cli_hlt(void) KEXEC_NORETURN;

/* Routines to get/set the control registers. */
#define CR_PROTOTYPES(n) \
  static uint32_t rcr##n(void); \
  static void lcr##n(uint32_t);
CR_PROTOTYPES(0)
CR_PROTOTYPES(2)
CR_PROTOTYPES(3)
CR_PROTOTYPES(4)
#undef CR_PROTOTYPES

/* Flush from the TLB the page whose address is passed as arg1. */
static void invlpg(const void* page_address);
/* Get the current processor number.
 * The MinGW folks did finally unbreak KeGetCurrentProcessorNumber(),
 * but it requires linking in libmingwex.a, which for kernel mode
 * software just really doesn't feel right. */
static uint32_t current_processor(void);
/* A convenient debug breakpoint. */
static void int3(void);
/* CPU feature identification */
static void cpuid(uint32_t idx, uint32_t* eax, uint32_t* ebx, uint32_t* ecx, uint32_t* edx);
/* Model-specific registers */
static uint64_t rdmsr(uint32_t addr);
static void wrmsr(uint32_t addr, uint64_t value);

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

#define CR_DEFINITIONS(n) \
static inline uint32_t rcr##n(void) \
{ \
  uint32_t cr##n; \
  __asm__ __volatile__ ("movl %%cr" #n ", %0" : "=r" (cr##n)); \
  return cr##n; \
} \
\
static inline void lcr##n(uint32_t cr##n) \
{ \
  __asm__ __volatile__ ("movl %0, %%cr" #n : : "r" (cr##n) : "memory"); \
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

static inline void cpuid(uint32_t idx, uint32_t* eax, uint32_t* ebx, uint32_t* ecx, uint32_t* edx)
{
  __asm__ __volatile__ ("cpuid" : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx) : "a" (idx));
}

static inline uint64_t rdmsr(uint32_t addr)
{
  uint32_t valhi, vallo;
  __asm__ __volatile__ ("rdmsr" : "=a" (vallo), "=d" (valhi) : "c" (addr));
  return vallo | ((uint64_t)valhi << 32);
}

static inline void wrmsr(uint32_t addr, uint64_t value)
{
  __asm__ __volatile__ ("wrmsr" : : "c" (addr), "a" ((uint32_t)(value & 0xffffffff)), "d" ((uint32_t)(value >> 32)));
}

#else
#error "Please port the inline assembly functions in inlineasm.h to your compiler's syntax."
#endif

CR_DEFINITIONS(0)
CR_DEFINITIONS(2)
CR_DEFINITIONS(3)
CR_DEFINITIONS(4)
#undef CR_DEFINITIONS

#endif

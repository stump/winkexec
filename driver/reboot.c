/* WinKexec: kexec for Windows
 * Copyright (C) 2008-2010 John Stumpo
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

/* Hook system reboot, and define the stuff needed to handle it. */

#include "linuxboot.h"
#include "reboot.h"
#include "buffer.h"

#include <ddk/ntimage.h>

/* NOTE: This is undocumented! */
typedef enum _FIRMWARE_REENTRY {
  HalHaltRoutine,
  HalPowerDownRoutine,
  HalRestartRoutine,
  HalRebootRoutine,
  HalInteractiveModeRoutine,
  HalMaximumRoutine,
} FIRMWARE_REENTRY, *PFIRMWARE_REENTRY;

typedef VOID KEXEC_NORETURN NTAPI(*halReturnToFirmware_t)(FIRMWARE_REENTRY);

static halReturnToFirmware_t real_HalReturnToFirmware;

/* More undocumentedness... */
typedef enum {
  SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

typedef struct {
  ULONG Reserved1;
  ULONG Reserved2;
#ifdef __x86_64__
  ULONG Reserved3;
  ULONG Reserved4;
#endif
  PVOID ImageBaseAddress;
  ULONG ImageSize;
  ULONG Flags;
  WORD Id;
  WORD Rank;
  WORD Unknown1;
  WORD NameOffset;
  BYTE Name[256];
} SYSTEM_MODULE;

typedef struct {
  ULONG ModulesCount;
  SYSTEM_MODULE Modules[0];
} SYSTEM_MODULE_INFORMATION;

NTSTATUS NTAPI ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

/* These are for poking around in loaded module images whose addresses
 * we find using the stuff above. */
#define RVA(base, rva, type) ((type)((char*)(base) + (size_t)rva))
#define DOS_HEADER(base) RVA((base), 0, PIMAGE_DOS_HEADER)
#define NT_HEADERS(base) RVA((base), DOS_HEADER(base)->e_lfanew, PIMAGE_NT_HEADERS)
#define DATADIR(base, diridx) ((PIMAGE_DATA_DIRECTORY)&(NT_HEADERS(base)->OptionalHeader.DataDirectory[(diridx)]))
#define IAT(base) RVA((base), DATADIR((base), IMAGE_DIRECTORY_ENTRY_IAT)->VirtualAddress, PVOID*)
#define IAT_NUM_ENTRIES(base) (DATADIR((base), IMAGE_DIRECTORY_ENTRY_IAT)->Size / sizeof(PVOID*))


static PVOID find_kernel_base(void)
{
  SYSTEM_MODULE_INFORMATION* module_info = NULL;
  ULONG length = 0;
  unsigned int i;
  unsigned int j;
  const PCHAR kernel_filenames[] = {"ntoskrnl.exe", "ntkrnlpa.exe",
                                    "ntkrnlmp.exe", "ntkrpamp.exe"};
  const unsigned int num_kernel_filenames = 4;

  /* Call QSI once to find out how much room to allocate for its output. */
  if (ZwQuerySystemInformation(SystemModuleInformation,
    module_info, length, &length) != STATUS_INFO_LENGTH_MISMATCH)
      return NULL;

  module_info = ExAllocatePoolWithTag(NonPagedPool,
    length, TAG('K', 'x', 'e', 'c'));

  /* Once more, with feeling. */
  if (!NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation,
    module_info, length, &length)))
  {
    ExFreePool(module_info);
    return NULL;
  }

  /* Find the kernel in the module list. */
  for (i = 0; i < module_info->ModulesCount; i++) {
    SYSTEM_MODULE* module = &module_info->Modules[i];
    const char* basename = strrchr((const char*)module->Name, '\\');
    if (basename == NULL)
      basename = (const char*)module->Name;
    else if (*basename != '\0')
      basename++;
    for (j = 0; j < num_kernel_filenames; j++) {
      if (strcasecmp(basename, kernel_filenames[j]) == 0)
      {
        PVOID kernel_base = module_info->Modules[i].ImageBaseAddress;
        ExFreePool(module_info);
        return kernel_base;
      }
    }
  }

  ExFreePool(module_info);
  return NULL;
}


/* Our "enhanced" version of HalReturnToFirmware.
   Drops through if we don't have a kernel to load or if an invalid
   operation type is specified.  The guts of ntoskrnl.exe will be
   tricked into calling this after everything is ready for "reboot."  */
static VOID KEXEC_NORETURN NTAPI KexecDoReboot(FIRMWARE_REENTRY RebootType)
{
  if (RebootType == HalRebootRoutine && KexecGetBufferSize(&KexecKernel))
    KexecLinuxBoot();
  else
    real_HalReturnToFirmware(RebootType);

  /* Should never happen. */
  KeBugCheckEx(0x42424242, 0x42424242, 0x42424242, 0x42424242, 0x42424242);
}

NTSTATUS KexecHookReboot(void)
{
  PVOID KernelBase;
  PVOID* iat;
  PVOID* iat_end;
  halReturnToFirmware_t* Target = NULL;
  PMDL Mdl;
  UNICODE_STRING hrtf_name;

  /* Find the kernel. */
  KernelBase = find_kernel_base();
  if (KernelBase == NULL
       || !MmIsAddressValid(KernelBase)
       || DOS_HEADER(KernelBase)->e_magic != 0x5a4d)
  {
    DbgPrint("Unable to find kernel base address.\n");
    return STATUS_UNSUCCESSFUL;
  }

  /* Find the kernel's import address table. */
  iat = IAT(KernelBase);
  iat_end = iat + IAT_NUM_ENTRIES(KernelBase);

  /* Find the kernel's import of HalReturnToFirmware. */
  RtlInitUnicodeString(&hrtf_name, L"HalReturnToFirmware");
  real_HalReturnToFirmware = MmGetSystemRoutineAddress(&hrtf_name);
  while (iat < iat_end) {
    if (*iat == real_HalReturnToFirmware) {
      Target = (halReturnToFirmware_t*)iat;
      break;
    }
    iat++;
  }

  if (Target == NULL) {
    DbgPrint("Unable to find HalReturnToFirmware in kernel import address table.\n");
    return STATUS_UNSUCCESSFUL;
  }

  /* Make it read-write. */
  if (!(Mdl = IoAllocateMdl(Target, sizeof(halReturnToFirmware_t), FALSE, FALSE, NULL)))
    return STATUS_UNSUCCESSFUL;
  MmBuildMdlForNonPagedPool(Mdl);
  Mdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;
  if (!(Target = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached,
    NULL, FALSE, HighPagePriority)))
  {
    IoFreeMdl(Mdl);
    return STATUS_UNSUCCESSFUL;
  }
  /* Hook it. */
  *Target = KexecDoReboot;
  /* And clean up. */
  MmUnmapLockedPages(Target, Mdl);
  IoFreeMdl(Mdl);

  return STATUS_SUCCESS;
}

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


static PVOID find_kernel_base(void)
{
  SYSTEM_MODULE_INFORMATION* module_info = NULL;
  ULONG length = 0;
  int i;
  int j;
  const PCHAR kernel_filenames[] = {"ntoskrnl.exe", "ntkrnlpa.exe",
                                    "ntkrnlmp.exe", "ntkrpamp.exe"};
  const int num_kernel_filenames = 4;

  /* Call QSI once to find out how much room to allocate for its output.
     TODO: look up correct error code for having to alloc the buffer */
  ZwQuerySystemInformation(SystemModuleInformation,
    module_info, length, &length);
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
    for (j = 0; j < num_kernel_filenames; j++) {
      if (strcasecmp(module_info->Modules[i].Name,
          kernel_filenames[j]) == 0)
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
  PIMAGE_NT_HEADERS NtHeaders;
  PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
  halReturnToFirmware_t* Target = NULL;
  PMDL Mdl;

  /* Find the kernel. */
  KernelBase = find_kernel_base();
  if (KernelBase == NULL
       || !MmIsAddressValid(KernelBase)
       || ((PIMAGE_DOS_HEADER)KernelBase)->e_magic != 0x5a4d)
  {
    DbgPrint("Unable to find kernel base address.\n");
    return STATUS_UNSUCCESSFUL;
  }

  /* Find the kernel's import table. */
  NtHeaders = KernelBase + ((PIMAGE_DOS_HEADER)KernelBase)->e_lfanew;
  ImportDescriptor = KernelBase +
    NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

  /* Find the kernel's import of HalReturnToFirmware from hal.dll. */
  while (ImportDescriptor->Name != 0) {
    if (strcasecmp(KernelBase + ImportDescriptor->Name, "hal.dll") == 0) {
      PIMAGE_THUNK_DATA NameThunk, CallThunk;

      for (NameThunk = KernelBase + ImportDescriptor->OriginalFirstThunk,
           CallThunk = KernelBase + ImportDescriptor->FirstThunk;
        NameThunk->u1.AddressOfData != 0; NameThunk++, CallThunk++)
      {
        PIMAGE_IMPORT_BY_NAME NamedImport = KernelBase + NameThunk->u1.AddressOfData;
        if (strcmp(NamedImport->Name, "HalReturnToFirmware") == 0)
          Target = (halReturnToFirmware_t*)CallThunk;
      }
    }
  }

  if (Target == NULL) {
    DbgPrint("Unable to find kernel import descriptor for hal.dll.");
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
  real_HalReturnToFirmware = *Target;
  *Target = KexecDoReboot;
  /* And clean up. */
  MmUnmapLockedPages(Target, Mdl);
  IoFreeMdl(Mdl);

  return STATUS_SUCCESS;
}

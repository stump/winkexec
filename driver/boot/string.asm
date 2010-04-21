; WinKexec: kexec for Windows
; Copyright (C) 2010 John Stumpo
;
; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with this program.  If not, see <http://www.gnu.org/licenses/>.

; Some string.h functions implemented in assembly for efficiency.

section .text
bits 32

; int memcmp(const void*, const void*, size_t);
global _memcmp
_memcmp:
  push edi
  push esi

  mov edi, dword [esp+12]
  mov esi, dword [esp+16]
  mov ecx, dword [esp+20]

  cld
  repz cmpsb
  movzx eax, byte [esi-1]
  movzx edx, byte [edi-1]
  sub eax, edx

  pop esi
  pop edi
  ret

; void* memcpy(void*, const void*, size_t);
global _memcpy
_memcpy:
  push edi
  push esi

  mov edi, dword [esp+12]
  mov esi, dword [esp+16]
  mov ecx, dword [esp+20]

  cld
  rep movsb
  mov eax, dword [esp+12]

  pop esi
  pop edi
  ret

; void* memmove(void*, const void*, size_t);
global _memmove
_memmove:
  push edi
  push esi

  mov edi, dword [esp+12]
  mov esi, dword [esp+16]
  mov ecx, dword [esp+20]

  cld
  cmp esi, edi
  ja .doCopy
  std
  lea edi, [edi+ecx-1]
  lea esi, [esi+ecx-1]
.doCopy:
  rep movsb
  cld
  mov eax, dword [esp+12]

  pop esi
  pop edi
  ret

; void *memset(void *s, int c, size_t n);
global _memset
_memset:
  push edi

  mov edi, dword [esp+8]
  mov eax, dword [esp+12]
  mov ecx, dword [esp+16]

  cld
  rep stosb
  mov eax, dword [esp+8]

  pop edi
  ret

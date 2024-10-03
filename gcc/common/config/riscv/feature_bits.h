/* Definition of RISC-V feature bits corresponding to
   libgcc/config/riscv/feature_bits.c
   Copyright (C) 2024 Free Software Foundation, Inc.

This file is part of GCC.

GCC is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3, or (at your option)
any later version.

GCC is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GCC; see the file COPYING3.  If not see
<http://www.gnu.org/licenses/>.  */

#define RISCV_FEATURE_BITS_LENGTH 2
struct {
  unsigned length;
  unsigned long long features[RISCV_FEATURE_BITS_LENGTH];
} riscv_feature_bits;

#define RISCV_VENDOR_FEATURE_BITS_LENGTH 1

struct {
  unsigned vendorID;
  unsigned length;
  unsigned long long features[RISCV_VENDOR_FEATURE_BITS_LENGTH];
} riscv_vendor_feature_bits;

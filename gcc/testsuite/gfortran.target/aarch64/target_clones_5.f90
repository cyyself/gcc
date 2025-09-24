! { dg-do compile }
! { dg-require-ifunc "" }
! { dg-additional-options "-O2 -fno-inline" }
! { dg-final { scan-assembler "module_sub\\.default" } }
! { dg-final { scan-assembler "module_sub\\.(avx|avx2|avx512f)" } }
! { dg-final { scan-assembler "module_sub\\.(resolver|ifunc)" } }
! { dg-final { scan-assembler "__utilities_MOD_calculate_func\\.default" } }
! { dg-final { scan-assembler "__utilities_MOD_calculate_func\\.(avx512f|avx2|avx)" } }
! { dg-final { scan-assembler "__utilities_MOD_calculate_func\\.(resolver|ifunc)" } }
!
! Test TARGET_CLONES attribute with modules and modern Fortran syntax
! This test verifies that target_clones works properly with:
! - Module procedures
! - Modern function declaration syntax
! - Different target specifications

MODULE utilities
  IMPLICIT NONE

CONTAINS

  SUBROUTINE module_sub(x, result)
    !GCC$ ATTRIBUTES TARGET_CLONES("default", "avx") :: module_sub
    REAL, INTENT(IN) :: x
    REAL, INTENT(OUT) :: result
    
    result = x * 2.0
  END SUBROUTINE module_sub

  ! Modern function syntax with explicit result type
  DOUBLE PRECISION FUNCTION calculate_func(x, y) RESULT(res)
    !GCC$ ATTRIBUTES TARGET_CLONES('default', 'avx512f') :: calculate_func
    
    DOUBLE PRECISION, INTENT(IN) :: x, y
    
    res = x * y + SIN(x) + COS(y)
  END FUNCTION calculate_func

END MODULE utilities
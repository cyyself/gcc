! { dg-do compile }
! { dg-require-ifunc "" }
! { dg-additional-options "-O2 -fno-inline -save-temps" }
! { dg-final { scan-assembler "sub_double\\..*\\.default" } }
! { dg-final { scan-assembler "sub_double\\..*\\.avx" } }
! { dg-final { scan-assembler "sub_double\\..*\\.(resolver|ifunc)" } }
! { dg-final { scan-assembler "sub_single\\..*\\.default" } }
! { dg-final { scan-assembler "sub_single\\..*\\.avx512f" } }
! { dg-final { scan-assembler "sub_single\\..*\\.(resolver|ifunc)" } }
!
! Test TARGET_CLONES attribute with both single and double quote syntax
! This test verifies that both 'string' and "string" syntax work correctly
! for target_clones attribute arguments.

PROGRAM TestQuoteSyntax
  IMPLICIT NONE

  INTEGER :: result1, result2

  CALL sub_double(1, 2, result1)
  CALL sub_single(3, 4, result2)
  
  WRITE(*,*) 'Results: ', result1, result2

CONTAINS

  ! Test with double quotes
  SUBROUTINE sub_double(a, b, sum_val)
    !GCC$ ATTRIBUTES TARGET_CLONES("default", "avx") :: sub_double
    INTEGER, INTENT(IN)  :: a, b
    INTEGER, INTENT(OUT) :: sum_val

    sum_val = a + b
  END SUBROUTINE sub_double

  ! Test with single quotes
  SUBROUTINE sub_single(a, b, sum_val)
    !GCC$ ATTRIBUTES TARGET_CLONES('default', 'avx512f') :: sub_single
    INTEGER, INTENT(IN)  :: a, b
    INTEGER, INTENT(OUT) :: sum_val

    sum_val = a * b
  END SUBROUTINE sub_single

END PROGRAM TestQuoteSyntax 
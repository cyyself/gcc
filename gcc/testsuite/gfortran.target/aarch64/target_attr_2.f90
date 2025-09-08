! { dg-do compile }
! { dg-require-effective-target avx2 }
! { dg-additional-options "-O0 -mavx2 -fno-inline" }
! { dg-final { scan-assembler "vaddss" } }
! { dg-final { scan-assembler "xmm" } }
!
PROGRAM TestTargetAVX2_SingleQuote
  IMPLICIT NONE
  REAL, DIMENSION(8) :: a, b, c
  INTEGER :: i

  DO i = 1, 8
    a(i) = i
    b(i) = i + 2
  END DO

  CALL vec_add(1)

CONTAINS
  SUBROUTINE vec_add(n)
    !GCC$ ATTRIBUTES TARGET('avx2') :: vec_add
    INTEGER, INTENT(IN) :: n
    REAL :: s, t, u
    INTEGER :: j
    DO j = 1, n
      s = a(1)
      t = b(1)
      u = s + t
      c(1) = u
    END DO
  END SUBROUTINE vec_add
END PROGRAM TestTargetAVX2_SingleQuote

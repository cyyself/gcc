! { dg-do compile }
! { dg-require-effective-target avx512f }
! { dg-additional-options "-O0 -mavx512f -mprefer-vector-width=512 -fno-inline" }
! { dg-final { scan-assembler "vmovss" } }
! { dg-final { scan-assembler "xmm" } }
!
PROGRAM TestTargetAVX512_Pos
  IMPLICIT NONE
  REAL, DIMENSION(16) :: a, b, c
  INTEGER :: i

  DO i = 1, 16
    a(i) = i
    b(i) = i + 1
  END DO

  ! Force emission of the internal procedure
  CALL vec_mul(1)

CONTAINS
  SUBROUTINE vec_mul(n)
    !GCC$ ATTRIBUTES TARGET("avx512f") :: vec_mul
    INTEGER, INTENT(IN) :: n
    REAL :: s, t, u
    INTEGER :: j
    DO j = 1, n
      s = a(1)
      t = b(1)
      u = s * t
      c(1) = u
    END DO
  END SUBROUTINE vec_mul
END PROGRAM TestTargetAVX512_Pos

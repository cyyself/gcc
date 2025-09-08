! { dg-do run }
! { dg-require-ifunc "" }
!
! Test TARGET_CLONES attribute runtime functionality
! This test verifies that cloned functions execute correctly at runtime.

PROGRAM TestTargetClonesRuntime
  IMPLICIT NONE

  INTEGER :: result
  DOUBLE PRECISION :: ans
  
  ! Test subroutine clones
  CALL compute_sum(15, 25, result)
  IF (result /= 40) CALL abort()

  ! Test function clones
  ans = compute_product(4.0D0, 5.0D0)
  IF (ABS(ans - 20.0D0) > 1.0D-10) CALL abort()

  WRITE(*,*) 'All tests passed'

CONTAINS

  SUBROUTINE compute_sum(a, b, sum_val)
    !GCC$ ATTRIBUTES TARGET_CLONES("default", "avx") :: compute_sum
    INTEGER, INTENT(IN)  :: a, b
    INTEGER, INTENT(OUT) :: sum_val

    sum_val = a + b
  END SUBROUTINE compute_sum

  FUNCTION compute_product(x, y)
    !GCC$ ATTRIBUTES TARGET_CLONES('default', 'avx512f') :: compute_product
    
    DOUBLE PRECISION :: compute_product
    DOUBLE PRECISION, INTENT(IN) :: x, y

    compute_product = x * y
  END FUNCTION compute_product

END PROGRAM TestTargetClonesRuntime 
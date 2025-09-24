! { dg-do compile }
! { dg-require-ifunc "" }
! { dg-final { scan-assembler "\\.*\\.default" } }
! { dg-final { scan-assembler "\\.*\\.avx" } }
! { dg-final { scan-assembler "\\.*\\.avx512f" } }
! { dg-final { scan-assembler "\\.*\\.resolver" } }

PROGRAM TestTargetClones
  IMPLICIT NONE

  INTEGER :: result
  DOUBLE PRECISION :: ans

  ! Call subroutine with target_clones attribute
  CALL MySub(5, 10, result)
  WRITE(*,*) 'The sum is: ', result

  ! Call function with target_clones attribute  
  ans = MyFunc(3.0D0, 2.0D0)
  WRITE(*,*) 'The result is: ', ans

CONTAINS

  SUBROUTINE MySub(a, b, sum_val)
    !GCC$ ATTRIBUTES TARGET_CLONES("default", "avx", "avx512f") :: MySub
    INTEGER, INTENT(IN)  :: a, b
    INTEGER, INTENT(OUT) :: sum_val

    sum_val = a + b
  END SUBROUTINE MySub

  FUNCTION MyFunc(x, y)
    !GCC$ ATTRIBUTES TARGET_CLONES("default", "avx", "avx512f") :: MyFunc
    
    DOUBLE PRECISION :: MyFunc
    DOUBLE PRECISION, INTENT(IN) :: x, y

    MyFunc = x * y + x / y
  END FUNCTION MyFunc

END PROGRAM TestTargetClones 
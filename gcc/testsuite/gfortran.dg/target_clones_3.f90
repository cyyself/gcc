! { dg-do compile }
! { dg-require-ifunc "" }
!
! Test TARGET_CLONES attribute error handling
! This test verifies that invalid syntax produces appropriate error messages.

PROGRAM TestTargetClonesErrors
  IMPLICIT NONE

CONTAINS

  ! Missing opening parenthesis
  SUBROUTINE test1()
    !GCC$ ATTRIBUTES TARGET_CLONES"default", "avx" :: test1  ! { dg-error "Expected .\\(. after TARGET_CLONES attribute" }
  END SUBROUTINE test1

  ! Missing closing parenthesis  
  SUBROUTINE test2()
    !GCC$ ATTRIBUTES TARGET_CLONES("default", "avx"  :: test2  ! { dg-error "Expected .,. or .\\). in TARGET_CLONES argument list" }
  END SUBROUTINE test2

  ! Non-string argument
  SUBROUTINE test3()
    !GCC$ ATTRIBUTES TARGET_CLONES("default", 123) :: test3  ! { dg-error "TARGET_CLONES arguments must be character constants" }
  END SUBROUTINE test3

  ! Missing quotes
  SUBROUTINE test4()
    !GCC$ ATTRIBUTES TARGET_CLONES(default, avx) :: test4  ! { dg-error "Expected quoted string argument in TARGET_CLONES" }
  END SUBROUTINE test4

  ! Empty argument list
  SUBROUTINE test5()
    !GCC$ ATTRIBUTES TARGET_CLONES() :: test5  ! { dg-error "Expected quoted string argument in TARGET_CLONES" }
  END SUBROUTINE test5

END PROGRAM TestTargetClonesErrors 
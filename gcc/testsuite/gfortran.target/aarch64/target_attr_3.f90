! { dg-do compile }
! { dg-additional-options "-fdiagnostics-plain-output" }
!
PROGRAM TestTargetErrors
  IMPLICIT NONE
CONTAINS
  SUBROUTINE e1()
    ! Missing quotes
    !GCC$ ATTRIBUTES TARGET(avx2) :: e1  ! { dg-error "Expected quoted string argument in TARGET attribute" }
  END SUBROUTINE e1

  SUBROUTINE e2()
    ! Non-string argument
    !GCC$ ATTRIBUTES TARGET(123) :: e2    ! { dg-error "TARGET attribute argument must be a character constant" }
  END SUBROUTINE e2

  SUBROUTINE e3()
    ! Missing '(' 
    !GCC$ ATTRIBUTES TARGET"avx2" :: e3  ! { dg-error "Expected '\\(' after TARGET attribute" }
  END SUBROUTINE e3

  SUBROUTINE e4()
    ! Empty list
    !GCC$ ATTRIBUTES TARGET() :: e4       ! { dg-error "Expected quoted string argument in TARGET attribute" }
  END SUBROUTINE e4
END PROGRAM TestTargetErrors

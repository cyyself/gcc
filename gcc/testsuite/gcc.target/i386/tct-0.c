/* { dg-do compile } */
/* { dg-require-ifunc "" } */
/* { dg-options "-ftarget-clones-table=${srcdir}/gcc.target/i386/tct-0.json" } */
/* { dg-final { scan-assembler "foo\.default" } } */
/* { dg-final { scan-assembler "foo\.arch_x86_64_v2" } } */
/* { dg-final { scan-assembler "foo\.arch_x86_64_v3" } } */
/* { dg-final { scan-assembler "foo\.arch_x86_64_v4" } } */

void foo() {

}

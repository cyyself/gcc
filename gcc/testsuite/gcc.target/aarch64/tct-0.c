/* { dg-do compile } */
/* { dg-require-ifunc "" } */
/* { dg-options "-ftarget-clones-table=${srcdir}/gcc.target/aarch64/tct-0.json" } */
/* { dg-final { scan-assembler "foo\.default" } } */
/* { dg-final { scan-assembler "foo\._Msve" } } */
/* { dg-final { scan-assembler "foo\._MsveMsve2" } } */

void foo() {

}

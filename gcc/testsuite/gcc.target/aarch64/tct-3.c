/* { dg-do compile } */
/* { dg-require-ifunc "" } */
/* { dg-options "-ftarget-clones-table=${srcdir}/gcc.target/aarch64/tct-3.json" } */
/* { dg-final { scan-assembler-not "foo\.default" } } */

void foo() /* { dg-warning "ignoring unsupported target clone version 'sve2\\+arch-never-exists' from target clones table" } */
{
}

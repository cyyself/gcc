/* { dg-do compile } */
/* { dg-require-ifunc "" } */
/* { dg-options "-ftarget-clones-table=${srcdir}/gcc.target/aarch64/tct-2.json" } */

void foo() {
} /* { dg-error "invalid JSON token: unescaped control char" } */

/* { dg-do compile } */
/* { dg-require-ifunc "" } */
/* { dg-options "-ftarget-clones-table=${srcdir}/gcc.target/aarch64/tct-4.json" } */

void foo() {
} /* { dg-error "No need to specify \"default\" in target clones table" } */

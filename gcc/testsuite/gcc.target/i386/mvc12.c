/* { dg-do compile } */
/* { dg-require-ifunc "" } */

__attribute__((target_clones("","arch=slm","arch=core-avx2", "default")))
int foo (); /* { dg-warning "empty string not valid for a .target_clones. version" } */

int
bar ()
{
  return foo();
}

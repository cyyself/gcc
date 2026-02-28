/* { dg-do compile } */
/* { dg-options "-O2 -fdump-ipa-sra -ffinite-loops"  } */

struct list
{
  struct list *next;
  int val;
};

__attribute__ ((noinline,target_clones("default", "arch=x86-64-v3")))
static int
reta (int *a)
{
  return *a;
}

__attribute__ ((noinline))
static int
kill (struct list *l, int *a)
{
  int v;
  while (l)
    {
      v = l->val;
      l = l->next;
    }
  return reta (a) + v;
}

int
test (struct list *l, int *a)
{
  return kill (l, a);
}

/* { dg-final { scan-ipa-dump-not "Created new node kill.isra"  "sra"  } } */
/* { dg-final { scan-ipa-dump "Created new node reta.isra"  "sra"  } } */

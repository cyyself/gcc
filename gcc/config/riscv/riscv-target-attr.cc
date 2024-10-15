/* Subroutines used for parsing target attribute for RISC-V.
   Copyright (C) 2023-2024 Free Software Foundation, Inc.

This file is part of GCC.

GCC is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3, or (at your option)
any later version.

GCC is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GCC; see the file COPYING3.  If not see
<http://www.gnu.org/licenses/>.  */

#define IN_TARGET_CODE 1

#define INCLUDE_MEMORY
#define INCLUDE_STRING
#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "target.h"
#include "tree.h"
#include "tm_p.h"
#include "diagnostic.h"
#include "opts.h"
#include "stringpool.h"
#include "attribs.h"
#include "riscv-subset.h"

//#include "common/config/riscv/feature_bits.h"

namespace {
class riscv_target_attr_parser
{
public:
  riscv_target_attr_parser (location_t loc)
    : m_found_arch_p (false)
    , m_found_tune_p (false)
    , m_found_cpu_p (false)
    , m_subset_list (nullptr)
    , m_loc (loc)
    , m_cpu_info (nullptr)
    , m_tune (nullptr)
  {
  }

  bool handle_arch (const char *);
  bool handle_cpu (const char *);
  bool handle_tune (const char *);

  void update_settings (struct gcc_options *opts) const;
  riscv_subset_list *get_subset_list();
private:
  const char *m_raw_attr_str;
  bool parse_arch (const char *);

  bool m_found_arch_p;
  bool m_found_tune_p;
  bool m_found_cpu_p;
  riscv_subset_list *m_subset_list;
  location_t m_loc;
  const  riscv_cpu_info *m_cpu_info;
  const char *m_tune;
};
}

/* All the information needed to handle a target attribute.
   NAME is the name of the attribute.
   HANDLER is the function that takes the attribute string as an argument.  */

struct riscv_attribute_info
{
  const char *name;
  bool (riscv_target_attr_parser::*handler) (const char *);
};

/* The target attributes that we support.  */

static const struct riscv_attribute_info riscv_attributes[]
  = {{"arch", &riscv_target_attr_parser::handle_arch},
     {"cpu", &riscv_target_attr_parser::handle_cpu},
     {"tune", &riscv_target_attr_parser::handle_tune}};

bool
riscv_target_attr_parser::parse_arch (const char *str)
{
  if (m_subset_list)
    delete m_subset_list;
  /* Check if it's setting full arch string.  */
  if (strncmp ("rv", str, strlen ("rv")) == 0)
    {
      m_subset_list = riscv_subset_list::parse (str, m_loc);

      if (m_subset_list == nullptr)
	goto fail;

      return true;
    }
  else
    {
      /* Parsing the extension list like "+<ext>[,+<ext>]*".  */
      size_t len = strlen (str);
      std::unique_ptr<char[]> buf (new char[len+1]);
      char *str_to_check = buf.get ();
      strcpy (str_to_check, str);
      const char *token = strtok_r (str_to_check, ",", &str_to_check);
      const char *local_arch_str = global_options.x_riscv_arch_string;
      m_subset_list = local_arch_str
		      ? riscv_subset_list::parse (local_arch_str, m_loc)
		      : riscv_cmdline_subset_list ()->clone ();
      m_subset_list->set_loc (m_loc);
      m_subset_list->set_allow_adding_dup (true);

      while (token)
	{
	  if (token[0] != '+')
	    {
	      error_at (
		m_loc,
		"unexpected arch for %<target()%> attribute: must start "
		"with + or rv");
	      goto fail;
	    }

	  const char *result = m_subset_list->parse_single_ext (token + 1);
	  /* Check parse_single_ext has consume all string.  */
	  if (*result != '\0')
	    {
	      error_at (
		m_loc,
		"unexpected arch for %<target()%> attribute: bad "
		"string found %<%s%>", token);
	      goto fail;
	    }

	  token = strtok_r (NULL, ",", &str_to_check);
	}

      m_subset_list->set_allow_adding_dup (false);
      m_subset_list->finalize ();
      return true;
    }
fail:
  if (m_subset_list != nullptr)
    {
      delete m_subset_list;
      m_subset_list = nullptr;
    }
  return false;
}

/* Handle the ARCH_STR argument to the arch= target attribute.  */

bool
riscv_target_attr_parser::handle_arch (const char *str)
{
  if (m_found_arch_p)
    error_at (m_loc, "%<target()%> attribute: arch appears more than once");
  m_found_arch_p = true;
  return parse_arch (str);
}

/* Handle the CPU_STR argument to the cpu= target attribute.  */

bool
riscv_target_attr_parser::handle_cpu (const char *str)
{
  if (m_found_cpu_p)
    error_at (m_loc, "%<target()%> attribute: cpu appears more than once");

  m_found_cpu_p = true;
  const riscv_cpu_info *cpu_info = riscv_find_cpu (str);

  if (!cpu_info)
    {
      error_at (m_loc, "%<target()%> attribute: unknown CPU %qs", str);
      return false;
    }

  if (m_subset_list == nullptr)
    {
      const char *arch_str = cpu_info->arch;
      m_subset_list = riscv_subset_list::parse (arch_str, m_loc);
      gcc_assert (m_subset_list);
    }

  m_cpu_info = cpu_info;
  return true;
}

/* Handle the TUNE_STR argument to the tune= target attribute.  */

bool
riscv_target_attr_parser::handle_tune (const char *str)
{
  if (m_found_tune_p)
    error_at (m_loc, "%<target()%> attribute: tune appears more than once");
  m_found_tune_p = true;
  const struct riscv_tune_info *tune = riscv_parse_tune (str, true);

  if (tune == nullptr)
    {
      error_at (m_loc, "%<target()%> attribute: unknown TUNE %qs", str);
      return false;
    }

  m_tune = tune->name;

  return true;
}

void
riscv_target_attr_parser::update_settings (struct gcc_options *opts) const
{
  if (m_subset_list)
    {
      std::string local_arch = m_subset_list->to_string (true);
      const char* local_arch_str = local_arch.c_str ();
      struct cl_target_option *default_opts
	= TREE_TARGET_OPTION (target_option_default_node);
      if (opts->x_riscv_arch_string != default_opts->x_riscv_arch_string)
	free (CONST_CAST (void *, (const void *) opts->x_riscv_arch_string));
      opts->x_riscv_arch_string = xstrdup (local_arch_str);

      riscv_set_arch_by_subset_list (m_subset_list, opts);
    }

  if (m_cpu_info)
    opts->x_riscv_cpu_string = m_cpu_info->name;

  if (m_tune)
    opts->x_riscv_tune_string = m_tune;
  else
    {
      if (m_cpu_info)
	opts->x_riscv_tune_string = m_cpu_info->tune;
    }
}

riscv_subset_list*
riscv_target_attr_parser::get_subset_list()
{
  return m_subset_list;
}
/* Parse ARG_STR which contains the definition of one target attribute.
   Show appropriate errors if any or return true if the attribute is valid.  */

static bool
riscv_process_one_target_attr (const char *arg_str,
			       location_t loc,
			       riscv_target_attr_parser &attr_parser)
{
  size_t len = strlen (arg_str);

  if (len == 0)
    {
      error_at (loc, "malformed %<target()%> attribute");
      return false;
    }

  std::unique_ptr<char[]> buf (new char[len+1]);
  char *str_to_check = buf.get();
  strcpy (str_to_check, arg_str);

  char *arg = strchr (str_to_check, '=');

  if (!arg)
    {
      error_at (
	loc,
	"attribute %<target(\"%s\")%> does not accept an argument",
	str_to_check);
      return false;
    }

  arg[0] = '\0';
  ++arg;
  for (const auto &attr : riscv_attributes)
    {
      /* If the names don't match up, or the user has given an argument
	 to an attribute that doesn't accept one, or didn't give an argument
	 to an attribute that expects one, fail to match.  */
      if (strncmp (str_to_check, attr.name, strlen (attr.name)) != 0)
	continue;

      return (&attr_parser->*attr.handler) (arg);
    }

  error_at (loc, "Got unknown attribute %<target(\"%s\")%>", str_to_check);
  return false;
}

/* Count how many times the character C appears in
   NULL-terminated string STR.  */

static unsigned int
num_occurrences_in_str (char c, char *str)
{
  unsigned int res = 0;
  while (*str != '\0')
    {
      if (*str == c)
	res++;

      str++;
    }

  return res;
}

/* Parse the string ARGS that contains the target attribute information
   and update the global target options space. */

bool
riscv_process_target_attr (const char *args, location_t loc) {
  size_t len = strlen (args);

  /* No need to emit warning or error on empty string here, generic code already
     handle this case.  */
  if (len == 0)
    {
      return false;
    }

  std::unique_ptr<char[]> buf (new char[len+1]);
  char *str_to_check = buf.get ();
  strcpy (str_to_check, args);

  /* Used to catch empty spaces between semi-colons i.e.
     attribute ((target ("attr1;;attr2"))).  */
  unsigned int num_semicolons = num_occurrences_in_str (';', str_to_check);

  /* Handle multiple target attributes separated by ';'.  */
  char *token = strtok_r (str_to_check, ";", &str_to_check);

  riscv_target_attr_parser attr_parser (loc);
  unsigned int num_attrs = 0;
  while (token)
    {
      num_attrs++;
      if (!riscv_process_one_target_attr (token, loc, attr_parser))
	return false;

      token = strtok_r (NULL, ";", &str_to_check);
    }

  if (num_attrs != num_semicolons + 1)
    {
      error_at (loc, "malformed %<target(\"%s\")%> attribute",
		args);
      return false;
    }

  /* Apply settings from target attribute.  */
  attr_parser.update_settings (&global_options);

  return true;
}

/* Parse the tree in ARGS that contains the target attribute information
   and update the global target options space.  */

static bool
riscv_process_target_attr (tree args, location_t loc)
{
  if (TREE_CODE (args) == TREE_LIST)
    {
      do
	{
	  tree head = TREE_VALUE (args);
	  if (head)
	    {
	      if (!riscv_process_target_attr (head, loc))
		return false;
	    }
	  args = TREE_CHAIN (args);
      } while (args);

      return true;
    }

  if (TREE_CODE (args) != STRING_CST)
    {
      error_at (loc, "attribute %<target%> argument not a string");
      return false;
    }

  return riscv_process_target_attr (TREE_STRING_POINTER (args), loc);
}

/* Implement TARGET_OPTION_VALID_ATTRIBUTE_P.
   This is used to process attribute ((target ("..."))).
   Note, that riscv_set_current_function() has not been called before,
   so we need must not mess with the current global_options, which
   likely belong to another function.  */

bool
riscv_option_valid_attribute_p (tree fndecl, tree, tree args, int)
{
  struct cl_target_option cur_target;
  bool ret;
  tree new_target;
  tree existing_target = DECL_FUNCTION_SPECIFIC_TARGET (fndecl);
  location_t loc = DECL_SOURCE_LOCATION (fndecl);

  /* Save the current target options to restore at the end.  */
  cl_target_option_save (&cur_target, &global_options, &global_options_set);

  /* If fndecl already has some target attributes applied to it, unpack
     them so that we add this attribute on top of them, rather than
     overwriting them.  */
  if (existing_target)
    {
      struct cl_target_option *existing_options
	= TREE_TARGET_OPTION (existing_target);

      if (existing_options)
	cl_target_option_restore (&global_options, &global_options_set,
				  existing_options);
    }
  else
    cl_target_option_restore (&global_options, &global_options_set,
			      TREE_TARGET_OPTION (target_option_default_node));

  /* Now we can parse the attributes and set &global_options accordingly.  */
  ret = riscv_process_target_attr (args, loc);
  /*
  // TODO: here we add target_version parser like aarch64
  if (ret)
    {
      tree version_attr = lookup_attribute ("target_version",
					    DECL_ATTRIBUTES (fndecl));
      if (version_attr != NULL_TREE)
	{
	  // Reapply any target_version attribute after target attribute.
	  // This should be equivalent to applying the target_version once
	  // after processing all target attributes.
	  tree version_args = TREE_VALUE (version_attr);
	  ret = aarch64_process_target_version_attr (version_args);
	}
    }
   */
  if (ret)
    {
      riscv_override_options_internal (&global_options);
      new_target = build_target_option_node (&global_options,
					     &global_options_set);
      DECL_FUNCTION_SPECIFIC_TARGET (fndecl) = new_target;
    }

  /* Restore current target options to original state.  */
  cl_target_option_restore (&global_options, &global_options_set, &cur_target);
  return ret;
}

/* Parse function multiversioning arch string, use the riscv_target_attr_parser
   to update information. */

static bool
riscv_parse_fmv_features (const char *str, location_t loc) 
{
  if (strcmp (str, "default") == 0)
    return true;
  
  riscv_target_attr_parser attr_parser (loc);
  if (!riscv_process_one_target_attr (str, loc, attr_parser))
    return false;
  
  attr_parser.update_settings (&global_options);
  return true;
  
}

/* Parse the tree in ARGS that contains the target_version attribute
   information and update the global target options space.  */

static bool
riscv_process_target_version_attr (tree args, location_t loc)
{
  if (TREE_CODE (args) == TREE_LIST)
    {
      if (TREE_CHAIN (args))
        {
          error ("attribute %<target_version%> has multiple values");
          return false;
        }
      args = TREE_VALUE (args);
    }

  if (!args || TREE_CODE (args) != STRING_CST)
    {
      error ("attribute %<target_version%> argument not a string");
      return false;
    }
  const char *str = TREE_STRING_POINTER (args);
  bool parse_res = riscv_parse_fmv_features (str, loc);

  return parse_res;
}


/* Implement TARGET_OPTION_VALID_VERSION_ATTRIBUTE_P.  This is used to
   process attribute ((target_version ("..."))).  */

bool
riscv_option_valid_version_attribute_p (tree fndecl, tree, tree args, int)
{
  //gcc_unreachable (); // TODO
  struct cl_target_option cur_target;
  bool ret;
  tree new_target;
  tree existing_target = DECL_FUNCTION_SPECIFIC_TARGET (fndecl);
  location_t loc = DECL_SOURCE_LOCATION (fndecl);

  /* Save the current target options to restore at the end.  */
  cl_target_option_save (&cur_target, &global_options, &global_options_set);

  /* If fndecl already has some target attributes applied to it, unpack
     them so that we add this attribute on top of them, rather than
     overwriting them.  */
  if (existing_target)
    {    
      struct cl_target_option *existing_options
        = TREE_TARGET_OPTION (existing_target);

      if (existing_options)
        cl_target_option_restore (&global_options, &global_options_set,
                                  existing_options);
    }    
  else
    cl_target_option_restore (&global_options, &global_options_set,
                              TREE_TARGET_OPTION (target_option_current_node));

  ret = riscv_process_target_version_attr (args, loc);

  /* Set up any additional state.  */
  if (ret)
    {
      riscv_override_options_internal (&global_options);
      new_target = build_target_option_node (&global_options,
                                             &global_options_set);
    }
  else
    new_target = NULL;

  if (fndecl && ret)
      DECL_FUNCTION_SPECIFIC_TARGET (fndecl) = new_target;
  
  cl_target_option_restore (&global_options, &global_options_set, &cur_target);

  return ret;
}

/* Types for recording extension to RISC-V C-API bitmask.  */
struct riscv_ext_bitmask_table_t {
  const char *ext;
  int groupid;
  int bit_position;
};

static const riscv_ext_bitmask_table_t riscv_ext_bitmask_table[] =
{
  {"i",                 0,  8},
  {"m",                 0, 12},
  {"a",                 0,  0},
  {"f",                 0,  5},
  {"d",                 0,  3},
  {"c",                 0,  2},
  {"v",                 0, 21},
  {"zba",               0, 27},
  {"zbb",               0, 28},
  {"zbs",               0, 33},
  {"zicboz",            0, 37},
  {"zbc",               0, 29},
  {"zbkb",              0, 30},
  {"zbkc",              0, 31},
  {"zbkx",              0, 32},
  {"zknd",              0, 41},
  {"zkne",              0, 42},
  {"zknh",              0, 43},
  {"zksed",             0, 44},
  {"zksh",              0, 45},
  {"zkt",               0, 46},
  {"zvbb",              0, 48},
  {"zvbc",              0, 49},
  {"zvkb",              0, 52},
  {"zvkg",              0, 53},
  {"zvkned",            0, 54},
  {"zvknha",            0, 55},
  {"zvknhb",            0, 56},
  {"zvksed",            0, 57},
  {"zvksh",             0, 58},
  {"zvkt",              0, 59},
  {"zfh",               0, 35},
  {"zfhmin",            0, 36},
  {"zihintntl",         0, 39},
  {"zvfh",              0, 50},
  {"zvfhmin",           0, 51},
  {"zfa",               0, 34},
  {"ztso",              0, 47},
  {"zacas",             0, 26},
  {"zicond",            0, 38},
  {"zihintpause",       0, 40},
  {"zve32x",            0, 60},
  {"zve32f",            0, 61},
  {"zve64x",            0, 62},
  {"zve64f",            0, 63},
  {"zve64d",            1,  0},
  {"zimop",             1,  1},
  {"zca",               1,  2},
  {"zcb",               1,  3},
  {"zcd",               1,  4},
  {"zcf",               1,  5},
  {"zcmop",             1,  6},
  {"zawrs",             1,  7},
  {NULL,               -1, -1}
};

/* Parse a function multiversioning feature string STR, as found in a
   target_version or target_clones attribute. */

static bool
parse_feature_bits (const char *str, struct riscv_feature_bits *res)
{
  //fprintf (stderr, "parse_feature_bits string is %s.\n", str);
  riscv_subset_list *subset_list;

  if (strcmp (str, "default") == 0) {
    res->length = 0;
    res->features[1] = 0;
    res->features[0] = 0;
    return true;
  }

  riscv_target_attr_parser attr_parser (UNKNOWN_LOCATION);
  if (!riscv_process_one_target_attr (str, UNKNOWN_LOCATION, attr_parser))
    return false;

  subset_list = attr_parser.get_subset_list();

  if (!subset_list)
    return false;

  res->length = RISCV_FEATURE_BITS_LENGTH;
  for (int i = 0; i < RISCV_FEATURE_BITS_LENGTH; ++i)
    res->features[i] = 0;

  const struct riscv_ext_bitmask_table_t *ext_bitmask_tab;
  for (ext_bitmask_tab = &riscv_ext_bitmask_table[0];
       ext_bitmask_tab->ext;
       ++ext_bitmask_tab)
    {
      if (subset_list->lookup (ext_bitmask_tab->ext) == NULL)
        continue;

      res->features[ext_bitmask_tab->groupid]
        |= 1ULL << ext_bitmask_tab->bit_position;
    }

  return true;
}

/* Compare priorities of two feature masks. Return:
     1: mask1 is higher priority
    -1: mask2 is higher priority
     0: masks are equal. 
   Since riscv_feature_bits has total 128 bits to be used as mask, 
   when counting the total 1s in the mask, the 1s in group1 needs to multiply a weight. */

static int
compare_feature_masks (struct riscv_feature_bits mask1,
                       struct riscv_feature_bits mask2)
{
  fprintf (stderr, "compare_feature_mask.\n");
  int pop1, pop2;
  int length1 = mask1.length, length2 = mask2.length;

  if (length1 > length2)
    return 1;
  else if (length1 < length2)
    return -1;
  else{
    pop1 = (popcount_hwi (mask1.features[length1 - 1]) * 64) + popcount_hwi (mask1.features[length1 - 2]);
    pop2 = (popcount_hwi (mask2.features[length2 - 1]) * 64) + popcount_hwi (mask2.features[length2 - 2]);
    //fprintf (stderr, "compare_feature_mask2 pop1 = %d, pop2 = %d.\n", pop1, pop2);
    if (pop1 > pop2)
      return 1;
    if (pop1 < pop2)
      return -1;
    auto diff_mask_group1 = mask1.features[1] ^ mask2.features[1];
    auto diff_mask_group0 = mask1.features[0] ^ mask2.features[0];
    if (diff_mask_group1 == 0ULL && diff_mask_group0 == 0ULL)
      return 0;
    else
      return 1;
  }
}

/* This parses the attribute arguments to target_version in DECL and the
   feature mask required to select those targets.  */

static struct riscv_feature_bits
get_feature_mask_for_version (tree decl)
{
  tree version_attr = lookup_attribute ("target_version",
                                        DECL_ATTRIBUTES (decl));
  struct riscv_feature_bits res;
  if (version_attr == NULL) {
    res.length = 0;
    res.features[0] = 0;
    res.features[1] = 0;
    return res;
  }
 
  const char *version_string = TREE_STRING_POINTER (TREE_VALUE (TREE_VALUE
                                                    (version_attr)));
  
  bool parse_res = parse_feature_bits (version_string, &res);

  gcc_assert (parse_res == true);

  return res;
}

/* Compare priorities of two version decls. Return:
     1: mask1 is higher priority
    -1: mask2 is higher priority
     0: masks are equal.  */

int
riscv_compare_version_priority (tree decl1, tree decl2)
{
  fprintf(stderr, "riscv_compare_version_priority\n");
  //gcc_unreachable ();
  struct riscv_feature_bits mask1 = get_feature_mask_for_version (decl1);
  struct riscv_feature_bits mask2 = get_feature_mask_for_version (decl2);

  return compare_feature_masks (mask1, mask2);
}

/* This function returns true if FN1 and FN2 are versions of the same function,
   that is, the target_version attributes of the function decls are different.
   This assumes that FN1 and FN2 have the same signature. */

bool
riscv_common_function_versions (tree fn1, tree fn2)
{
  if (TREE_CODE (fn1) != FUNCTION_DECL
      || TREE_CODE (fn2) != FUNCTION_DECL)
    return false;

  fprintf(stderr, "riscv_common_function_versions\n");

  return false; // TODO: return (riscv_compare_version_priority (fn1, fn2) != 0);
  //return (riscv_compare_version_priority (fn1, fn2) != 0);
}


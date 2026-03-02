/* Pass for parsing functions with multiple target attributes.

   Contributed by Evgeny Stupachenko <evstupac@gmail.com>

   Copyright (C) 2015-2026 Free Software Foundation, Inc.

This file is part of GCC.

GCC is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation; either version 3, or (at your option) any later
version.

GCC is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License
along with GCC; see the file COPYING3.  If not see
<http://www.gnu.org/licenses/>.  */

#include "config.h"
#include <fstream>
#define INCLUDE_MAP
#define INCLUDE_STRING
#define INCLUDE_SSTREAM
#include "system.h"
#include "coretypes.h"
#include "backend.h"
#include "tree.h"
#include "stringpool.h"
#include "gimple.h"
#include "diagnostic-core.h"
#include "gimple-ssa.h"
#include "cgraph.h"
#include "tree-pass.h"
#include "target.h"
#include "attribs.h"
#include "pretty-print.h"
#include "gimple-iterator.h"
#include "gimple-walk.h"
#include "tree-inline.h"
#include "intl.h"
#include "json-parsing.h"

/* Walker callback that replaces all FUNCTION_DECL of a function that's
   going to be versioned.  */

static tree
replace_function_decl (tree *op, int *walk_subtrees, void *data)
{
  struct walk_stmt_info *wi = (struct walk_stmt_info *) data;
  cgraph_function_version_info *info = (cgraph_function_version_info *)wi->info;

  if (TREE_CODE (*op) == FUNCTION_DECL
      && info->this_node->decl == *op)
    {
      *op = info->dispatcher_resolver;
      *walk_subtrees = 0;
    }

  return NULL;
}

/* In target FMV attributes, if the call in NODE has multiple target attribute
   with multiple fields, replace it with calls to the dispatched symbol and
   create the dispatcher body (once).

   In target_version semantics, if it is a lone annotated default, then
   the dispatched symbol is changed to be an alias and no resolver is
   required.  Otherwise, redirect all calls and references to the dispatched
   symbol, but only create the resolver body if the default version is
   implemented.  */

static void
create_dispatcher_calls (struct cgraph_node *node)
{
  ipa_ref *ref;

  if (!targetm.has_ifunc_p ())
    {
      error_at (DECL_SOURCE_LOCATION (node->decl),
		"the call requires %<ifunc%>, which is not"
		" supported by this target");
      return;
    }
  else if (!targetm.get_function_versions_dispatcher)
    {
      error_at (DECL_SOURCE_LOCATION (node->decl),
		"target does not support function version dispatcher");
      return;
    }

  tree idecl = targetm.get_function_versions_dispatcher (node->decl);
  if (!idecl)
    {
      error_at (DECL_SOURCE_LOCATION (node->decl),
		"default %<target_clones%> attribute was not set");
      return;
    }

  cgraph_node *inode = cgraph_node::get (idecl);
  gcc_assert (inode);
  cgraph_function_version_info *inode_info = inode->function_version ();
  gcc_assert (inode_info);

  tree resolver_decl = NULL;

  /* For target_version semantics, if there is a lone default declaration
     it needs to be mangled, with an alias from the dispatched symbol to the
     default version.  */
  if (!TARGET_HAS_FMV_TARGET_ATTRIBUTE
      && TREE_STATIC (node->decl)
      && inode_info->next
      && !inode_info->next->next)
    {
      inode->alias = true;
      inode->alias_target = inode_info->next->this_node->decl;
      inode->externally_visible = true;
      if (!inode->analyzed)
	inode->resolve_alias
	  (cgraph_node::get (inode_info->next->this_node->decl));

      DECL_ATTRIBUTES (idecl)
	= make_attribute ("alias",
			  IDENTIFIER_POINTER
			    (DECL_ASSEMBLER_NAME
			       (inode_info->next->this_node->decl)),
			  DECL_ATTRIBUTES (node->decl));
      TREE_USED (idecl) = true;
      DECL_EXTERNAL (idecl) = false;
      TREE_STATIC (idecl) = true;
      return;
    }
  /* In target_version semantics, only create the resolver if the
     default node is implemented.  */
  else if (TARGET_HAS_FMV_TARGET_ATTRIBUTE || TREE_STATIC (node->decl))
    {
      resolver_decl = targetm.generate_version_dispatcher_body (inode);
      /* Update aliases.  */
      inode->alias = true;
      inode->alias_target = resolver_decl;
      if (!inode->analyzed)
	inode->resolve_alias (cgraph_node::get (resolver_decl));
    }

  auto_vec<cgraph_edge *> edges_to_redirect;
  /* We need to capture the references by value rather than just pointers to them
     and remove them right away, as removing them later would invalidate what
     some other reference pointers point to.  */
  auto_vec<ipa_ref> references_to_redirect;

  while (node->iterate_referring (0, ref))
    {
      references_to_redirect.safe_push (*ref);
      ref->remove_reference ();
    }

  /* We need to remember NEXT_CALLER as it could be modified in the loop.  */
  for (cgraph_edge *e = node->callers; e ; e = e->next_caller)
    edges_to_redirect.safe_push (e);

  if (!edges_to_redirect.is_empty () || !references_to_redirect.is_empty ())
    {
      /* Redirect edges.  */
      unsigned i;
      cgraph_edge *e;
      FOR_EACH_VEC_ELT (edges_to_redirect, i, e)
	{
	  e->redirect_callee (inode);
	  cgraph_edge::redirect_call_stmt_to_callee (e);
	}

      /* Redirect references.  */
      FOR_EACH_VEC_ELT (references_to_redirect, i, ref)
	{
	  if (ref->use == IPA_REF_ADDR)
	    {
	      struct walk_stmt_info wi;
	      memset (&wi, 0, sizeof (wi));
	      wi.info = (void *)node->function_version ();

	      if (dyn_cast<varpool_node *> (ref->referring))
		{
		  hash_set<tree> visited_nodes;
		  walk_tree (&DECL_INITIAL (ref->referring->decl),
			     replace_function_decl, &wi, &visited_nodes);
		}
	      else
		{
		  gimple_stmt_iterator it = gsi_for_stmt (ref->stmt);
		  if (ref->referring->decl != resolver_decl)
		    walk_gimple_stmt (&it, NULL, replace_function_decl, &wi);
		}

	      symtab_node *source = ref->referring;
	      source->create_reference (inode, IPA_REF_ADDR);
	    }
	  else if (ref->use == IPA_REF_ALIAS)
	    {
	      symtab_node *source = ref->referring;
	      source->create_reference (inode, IPA_REF_ALIAS);
	      if (inode->get_comdat_group ())
		{
		  if (source->same_comdat_group)
		    source->remove_from_same_comdat_group ();
		  source->add_to_same_comdat_group (inode);
		}
	    }
	  else
	    gcc_unreachable ();
	}
    }

  if (node->definition)
    {
      /* FIXME: copy of cgraph_node::make_local that should be cleaned up
		in next stage1.  */
      node->make_decl_local ();
      node->set_section (NULL);
      node->set_comdat_group (NULL);
      node->externally_visible = false;
      node->forced_by_abi = false;

      DECL_ARTIFICIAL (node->decl) = 1;
      node->force_output = true;
    }
}

/*  Creates target clone of NODE.  */

static cgraph_node *
create_target_clone (cgraph_node *node, bool definition, char *name,
		     tree attributes)
{
  cgraph_node *new_node;

  if (definition)
    {
      new_node
	= node->create_version_clone_with_body (vNULL, NULL, NULL, NULL, NULL,
						name, attributes, false);
      if (new_node == NULL)
	return NULL;
      new_node->force_output = true;
    }
  else
    {
      tree new_decl = copy_node (node->decl);
      new_node = cgraph_node::get_create (new_decl);
      DECL_ATTRIBUTES (new_decl) = attributes;
      /* Generate a new name for the new version.  */
      tree fname = clone_function_name (node->decl, name);
      symtab->change_decl_assembler_name (new_node->decl, fname);
    }
  return new_node;
}

/* Skip functions that are declared but not defined.  Also skip C++
   virtual functions, as they cannot be cloned.  The same logic is in the
   function expand_target_clones below.  */
static bool node_versionable_function_p (cgraph_node *node)
{
  return (!node->definition
	  || (!node->alias && tree_versionable_function_p (node->decl)))
          && !DECL_DECLARED_INLINE_P (node->decl) 
	  && !DECL_VIRTUAL_P (node->decl)
	  && (!DECL_FUNCTION_VERSIONED (node->decl)
	      || is_function_default_version (node->decl));
}

/* If the function in NODE has multiple target attributes
   create the appropriate clone for each valid target attribute.  */

static bool
expand_target_clones (struct cgraph_node *node, bool definition,
		      std::map <std::string, auto_vec<string_slice> >
		      &clone_map)
{
  /* Parsing target attributes separated by TARGET_CLONES_ATTR_SEPARATOR.  */
  tree attr_target = lookup_attribute ("target_clones",
				       DECL_ATTRIBUTES (node->decl));
  int num_defaults = 0;
  auto_vec<string_slice> attr_list = get_clone_versions (node->decl,
							 &num_defaults);
  /* When target_clones attribute is present, but there is no valid
     entries, we believe there can be another function with the same name
     but has "target_version" specified, so we remove this function, this
     only applies to aarch64 for now.  For RISC-V, it will give an error
     earlier.

     This can barely happen in practice as the "default" attribute can
     always be added to avoid this.  Thus, we even skip target clones table
     lookup in this case.  Any following architectures that use
     "target_version" semantics should aware of this behaviour if it will
     not give error but just skip during attribute checking.  */
  if (!TARGET_HAS_FMV_TARGET_ATTRIBUTE && attr_list.is_empty () && attr_target)
    {
      node->remove ();
      return false;
    }

  if (DECL_INITIAL (node->decl) != NULL_TREE)
    {
      auto it = clone_map.find (IDENTIFIER_POINTER (
				DECL_ASSEMBLER_NAME_RAW (node->decl)));
      /* Also try DECL_NAME for Fortran module functions where the JSON
	 profile may use the short name (e.g., "rhs3d_tile") while the
	 assembler name is mangled (e.g., "__rhs3d_mod_MOD_rhs3d_tile").
	 Skip nested/contained functions (decl_function_context != NULL)
	 because ifunc dispatch does not support static chains.
	 Skip clones (clone_of != NULL) to avoid expanding IPA-generated
	 clones that were derived from the original function.  */
      if (it == clone_map.end () && DECL_NAME (node->decl)
	  && !decl_function_context (node->decl)
	  && !node->clone_of)
	it = clone_map.find (IDENTIFIER_POINTER (DECL_NAME (node->decl)));
      if (it != clone_map.end () && node_versionable_function_p (node))
	{
	  /* Merge valid target attributes from -ftarget-clones-table.  */
	  for (string_slice attr : it->second)
	    if (targetm.check_target_clone_version (attr, NULL))
	      attr_list.safe_push (attr);
	    else
		warning_at (DECL_SOURCE_LOCATION (node->decl),
			    0, "ignoring unsupported target clone "
			    "version '%B' from target clones table",
			    &attr);

	  if (num_defaults == 0)
	    {
	      /* No default in the source attribute, add one.  */
	      attr_list.safe_push ("default");
	      num_defaults = 1;
	    }
	}
    }

  /* If there is no target_clones attribute, nothing to do.  */
  if (attr_list.is_empty ())
      return false;

  /* No need to clone for 1 target attribute.  */
  if (attr_list.length () == 1 && TARGET_HAS_FMV_TARGET_ATTRIBUTE)
    {
      warning_at (DECL_SOURCE_LOCATION (node->decl),
		  0, "single %<target_clones%> attribute is ignored");
      return false;
    }

  /* For target_version semantics, a target clone with just a default version
     is the same as an unannotated decl, so can ignore.  */
  if (!TARGET_HAS_FMV_TARGET_ATTRIBUTE
      && attr_list.length () == 1
      && num_defaults == 1)
    return false;

  if (node->definition
      && (node->alias || !tree_versionable_function_p (node->decl)))
    {
      auto_diagnostic_group d;
      error_at (DECL_SOURCE_LOCATION (node->decl),
		"clones for %<target_clones%> attribute cannot be created");
      const char *reason = NULL;
      if (lookup_attribute ("noclone", DECL_ATTRIBUTES (node->decl)))
	reason = G_("function %q+F can never be copied "
		    "because it has %<noclone%> attribute");
      else if (node->alias)
	reason
	  = "%<target_clones%> cannot be combined with %<alias%> attribute";
      else
	reason = copy_forbidden (DECL_STRUCT_FUNCTION (node->decl));
      if (reason)
	inform (DECL_SOURCE_LOCATION (node->decl), reason, node->decl);
      return false;
    }

  /* Disallow multiple defaults.  */
  if (num_defaults > 1)
    {
      error_at (DECL_SOURCE_LOCATION (node->decl),
		"multiple %<default%> targets were set");
      return false;
    }

  /* For target FMV semantics, where target and target_clone mixing
     is not supported, disallow target clones with no defaults.  */
  if (TARGET_HAS_FMV_TARGET_ATTRIBUTE && num_defaults == 0)
    {
      error_at (DECL_SOURCE_LOCATION (node->decl),
		"%<default%> target was not set");
      return false;
    }

  /* Disallow any empty values in the clone attr.  */
  for (string_slice attr : attr_list)
    if (attr.empty () || !attr.is_valid ())
      {
	error_at (DECL_SOURCE_LOCATION (node->decl),
		  "an empty string cannot be in %<target_clones%> attribute");
	return false;
      }

  string_slice new_attr_name = TARGET_HAS_FMV_TARGET_ATTRIBUTE
			       ? "target"
			       : "target_version";

  cgraph_function_version_info *node_v = node->function_version ();

  if (!node_v)
    node_v = node->insert_new_function_version ();

  /* If this target_clones contains a default, then convert this node to the
     default.  If this node does not contain default (this is only possible
     in target_version semantics) then remove the node.  This is safe at this
     point as only target_clones declarations containing default version is
     resolvable so this decl will have no calls/references.  */

  tree attrs = remove_attribute ("target_clones",
				  DECL_ATTRIBUTES (node->decl));
  tree assembler_name = node_v->assembler_name;

  /* Change the current node into the default node.  */
  if (num_defaults == 1)
    {
      /* Setting new attribute to initial function.  */
      tree attributes = make_attribute (new_attr_name, "default", attrs);
      DECL_ATTRIBUTES (node->decl) = attributes;
      DECL_FUNCTION_VERSIONED (node->decl) = true;

      node->is_target_clone = true;
      node->local = false;

      /* Remangle base node after new target version string set.  */
      tree id = targetm.mangle_decl_assembler_name (node->decl, assembler_name);
      symtab->change_decl_assembler_name (node->decl, id);
    }
  else
    {
      /* Target clones without a default are only allowed for target_version
	 semantics where we can have target_clones/target_version mixing.  */
      gcc_assert (!TARGET_HAS_FMV_TARGET_ATTRIBUTE);

      /* If there isn't a default version, can safely remove this version.
	 The node itself gets removed after the other versions are created.  */
      cgraph_function_version_info *temp = node_v;
      node_v = node_v->next ? node_v->next : node_v->prev;
      cgraph_node::delete_function_version (temp);
    }

  for (string_slice attr : attr_list)
    {
      /* Skip default nodes.  */
      if (attr == "default")
	continue;

      /* Create new target clone.  */
      tree attributes = make_attribute (new_attr_name, attr, attrs);

      cgraph_node *new_node
	= create_target_clone (node, definition, NULL, attributes);
      if (new_node == NULL)
	return false;
      new_node->local = false;

      DECL_FUNCTION_VERSIONED (new_node->decl) = true;
      if (!node_v)
	node_v = new_node->insert_new_function_version ();
      else
	cgraph_node::add_function_version (node_v, new_node->decl);

      /* Use the base node's assembler name for all created nodes.  */
      new_node->function_version ()->assembler_name = assembler_name;
      new_node->is_target_clone = true;

      /* Mangle all new nodes.  */
      tree id = targetm.mangle_decl_assembler_name
	(new_node->decl, new_node->function_version ()->assembler_name);
      symtab->change_decl_assembler_name (new_node->decl, id);
    }

  /* If there are no default versions in the target_clones, this node is not
     reused, so can delete this node.  */
  if (num_defaults == 0)
    node->remove ();

  return true;
}

/* When NODE is part of an FMV function set, consider all callees and check if
   any can provably always resolve a certain version and then call that version
   directly.  */

static void
redirect_to_specific_clone (cgraph_node *node)
{
  if (!targetm.compare_version_priority || !optimize)
    return;

  /* We need to remember NEXT_CALLER as it could be modified in the loop.  */
  for (cgraph_edge *e = node->callees; e ; e = e->next_callee)
    {
      /* Only if this is a call to a dispatched symbol.  */
      if (!e->callee->dispatcher_function)
	continue;

      cgraph_function_version_info *callee_v
	= e->callee->function_version ();
      cgraph_function_version_info *caller_v
	= e->caller->function_version ();

      gcc_assert (callee_v);

      /* Find the default nodes for both callee and caller (if present).  */
      cgraph_function_version_info *callee_default_v = callee_v->next;
      cgraph_function_version_info *caller_default_v = caller_v;
      if (caller_v)
	{
	  while (caller_default_v->prev)
	    caller_default_v = caller_default_v->prev;
	  if (!is_function_default_version (caller_default_v->this_node->decl))
	    caller_default_v = NULL;
	}

      /* If this is not the TU that contains the definition of the default
	 version we are not guaranteed to have visibility of all versions
	 so cannot reason about them.  */
      if (!callee_default_v
	  || !callee_default_v->this_node->binds_to_current_def_p ())
	continue;

      cgraph_function_version_info *highest_callable_fn = NULL;
      for (cgraph_function_version_info *ver = callee_v->next;
	   ver;
	   ver = ver->next)
	if (targetm.target_option.functions_b_resolvable_from_a
	      (node->decl, ver->this_node->decl, node->decl))
	  highest_callable_fn = ver;

      if (!highest_callable_fn)
	continue;

      bool inlinable = true;

      /* If there are higher priority versions of callee and caller has no
	 more version information, then not callable.  */
      if (highest_callable_fn->next)
	{
	  /* If this is not the TU where the callee default is defined then
	     cannot reason about the caller versions.  */
	  if (!caller_default_v
	      || !caller_default_v->this_node->binds_to_current_def_p ())
	    continue;

	  /* If every higher priority version would imply a higher priority
	     version of caller would have been selected, then this is
	     callable.  */
	  for (cgraph_function_version_info *callee_ver
	       = highest_callable_fn->next;
	       callee_ver; callee_ver = callee_ver->next)
	    {
	      bool is_possible = true;
	      for (cgraph_function_version_info *caller_ver = caller_v->next;
		   caller_ver; caller_ver = caller_ver->next)
		if (targetm.target_option.functions_b_resolvable_from_a
		      (callee_ver->this_node->decl, caller_ver->this_node->decl,
		       node->decl))
		  {
		    is_possible = false;
		    break;
		  }
	      if (is_possible)
		{
		  inlinable = false;
		  break;
		}
	    }
	}
      if (inlinable)
	{
	  e->redirect_callee (highest_callable_fn->this_node);
	  cgraph_edge::redirect_call_stmt_to_callee (e);
	}
    }
}

/* Checks if NODE is in the 'simple' target_clones case, which is where NODE
   is a declaration annotated with target_clones containing the default, and it
   is the sole function declaration in the FMV function set.  */

static bool
is_simple_target_clones_case (cgraph_node *node)
{
  /* target attribute semantics doesnt support the complex case,
     so this is always true.  */
  if (TARGET_HAS_FMV_TARGET_ATTRIBUTE)
    return true;

  int num_defaults = 0;
  auto versions = get_clone_versions (node->decl, &num_defaults);
  if (versions.is_empty () || num_defaults != 1)
    return false;

  cgraph_function_version_info *fv = node->function_version ();

  if (fv && (fv->next || fv->prev))
    return false;

  return true;
}

/* Initialize the clone map from the target clone table JSON file.  Specified
   by the -ftarget-clone-table option.  The map is a mapping from symbol name
   to a string with target clones attributes separated by
   TARGET_CLONES_ATTR_SEPARATOR.  */
static std::map <std::string, auto_vec<string_slice> >
init_clone_map (void)
{
  std::map <std::string, auto_vec<string_slice> > res;
  if (! target_clones_table)
    return res;

  /* Take target string from TARGET_NAME, this macro looks like
     "x86_64-linux-gnu" and we need to strip all the suffixes
     after the first dash, so it becomes "x86_64".  */
  std::string target = TARGET_NAME;
  if (target.find ('-') != std::string::npos)
    target.erase (target.find ('-'));

  /* Open the target clone table file and read to a string.  */
  std::ifstream json_file (target_clones_table);
  if (json_file.fail ())
    {
      error ("cannot open target clone table file %s",
	     target_clones_table);
      return res;
    }
  std::stringstream ss_buf;
  ss_buf << json_file.rdbuf ();
  std::string json_str = ss_buf.str ();

  /* Parse the JSON string.
     The JSON string format looks like this:
     {
       "symbol_name1": {
	 "target1": ["clone1", "clone2", ...],
	 "target2": ["clone1", "clone2", ...],
       },
       ...
     }
     where symbol_name is the ASM name of the function mangled by the
     frontend.  The target1 and target2 are the targets, which can be
     "x86_64", "aarch64", "riscv64", etc.  The clone1, clone2, etc are the
     target clones attributes, which can be "avx2", "avx512" etc.  Note that
     there is no need to specify the "default" target clone, it is
     automatically added by the pass.  */
  json::parser_result_t result = json::parse_utf8_string (
    json_str.size (), json_str.c_str (), true, NULL);
  if (auto json_err = result.m_err.get ())
    {
      error ("error parsing target clone table file %s: %s",
	     target_clones_table, json_err->get_msg ());
      return res;
    }

  auto json_val = result.m_val.get ();
  auto kind = json_val->get_kind ();
  if (kind != json::JSON_OBJECT)
    {
      error ("target clone table file %s is not a JSON object",
	     target_clones_table);
      return res;
    }
  auto json_obj = static_cast<const json::object *> (json_val);
  for (const auto &json_entry : json_obj->get_map ())
    {
      const char *symbol_name = json_entry.first;
      auto symbol_val = json_entry.second;
      if (!symbol_val || symbol_val->get_kind () != json::JSON_OBJECT)
	continue;
      auto symbol_obj = static_cast<const json::object *> (symbol_val);
      auto cur_target_val = symbol_obj->get (target.c_str ());
      if (!cur_target_val
	  || cur_target_val->get_kind () != json::JSON_ARRAY)
	continue;
      auto cur_target_array = static_cast<const json::array *>
	(cur_target_val);
      for (unsigned j = 0; j < cur_target_array->length (); j++)
	{
	  auto target_str_val = cur_target_array->get (j);
	  if (target_str_val->get_kind () != json::JSON_STRING)
	    error ("target clones attribute is not a string");
	  const char *target_str
	    = static_cast<const json::string *> (target_str_val)->get_string ();
	  if (strcmp (target_str, "default") == 0)
	      error ("No need to specify \"default\" in target clones table");
	  res[symbol_name].safe_push (string_slice (ggc_strdup (target_str)));
	}
    }
  return res;
}

static unsigned int
ipa_target_clone (bool early)
{
  static int non_early_pass_count = 0;
  struct cgraph_node *node;
  auto_vec<cgraph_node *> to_dispatch;
  std::map <std::string, auto_vec<string_slice> > clone_map
    = init_clone_map ();

  /* With -ftarget-clones-table enabled, pass_target_clone(false) is scheduled
     twice:
       1. Before IPA-SRA: expand all target_clones (annotation and table-based).
       2. After IPA-SRA: dispatch ISRA-generated FMV clones.  */
  bool process_table = false;
  if (!early && target_clones_table)
    {
      non_early_pass_count++;
      if (non_early_pass_count == 1)
	{
	  /* First non-early: expand all FMV.  */
	  process_table = true;
	}
      else if (non_early_pass_count == 2)
	{
	  /* Second non-early (after IPA-SRA): ISRA dispatch only.  */
	  process_table = false;
	}
      else
	return 0;
    }

  /* Don't need to do anything early for target attribute semantics.  */
  if (early && TARGET_HAS_FMV_TARGET_ATTRIBUTE)
    return 0;

  /* For target attribute semantics, this pass skips the early phase, and in
     the later stage is only responsible for expanding and dispatching
     target_clone declarations, as target annotated functions are dispatched
     in the front end.

     The expanding and dispatching can be done at the late stage as the
     target_clone functions aren't allowed to be part of a larger FMV set, so
     all versions will all have the same body, so early optimisations are safe
     to treat a call to a target_clones set as a call to one function.

     For target_version semantics, this pass is responsible for expanding
     target_clones and dispatching all FMV function sets, including ones only
     made up of target_version declarations.

     Cases where there is more than one declaration must be expanded and
     dispatched at the early stage, as the declarations may have different
     bodies, and so the early optimisation passes would not be valid.

     The late stage is only used for the expansion and dispatching of the simple
     case where the FMV set is defined by a single target_clone attribute.  */

  FOR_EACH_FUNCTION_REMOVABLE (node)
    {
      /* In the early stage, we need to expand any target clone that is not
	 the simple case.  Simple cases are dispatched in the later stage.  */

      /* For table-based FMV, defer expansion to the second non-early pass
	 (after IPA-CP/IPA-SRA) so IPA optimizations can create constprop
	 and ISRA clones of the original function first.  */
      if (target_clones_table && !process_table && !early)
	{
	  bool found_in_table = false;
	  if (DECL_INITIAL (node->decl))
	    {
	      auto it = clone_map.find (
		IDENTIFIER_POINTER (DECL_ASSEMBLER_NAME_RAW (node->decl)));
	      if (it == clone_map.end () && DECL_NAME (node->decl)
		  && !decl_function_context (node->decl)
		  && !node->clone_of)
		it = clone_map.find (
		  IDENTIFIER_POINTER (DECL_NAME (node->decl)));
	      found_in_table = (it != clone_map.end ());
	    }
	  if (found_in_table)
	    continue;
	}

      if (early == !is_simple_target_clones_case (node))
	if (expand_target_clones (node, node->definition, clone_map)
	    && TARGET_HAS_FMV_TARGET_ATTRIBUTE)
	  /* In non target_version semantics, dispatch all target clones.  */
	  to_dispatch.safe_push (node);
    }

  /* In target_version semantics dispatch all FMV function sets with a default
     implementation in the early stage.
     Also dispatch any default versions generated by expanding target_clones
     in the late stage.  */

  if (!TARGET_HAS_FMV_TARGET_ATTRIBUTE)
    FOR_EACH_FUNCTION (node)
      {
  cgraph_function_version_info *v = node->function_version ();
  const char *asm_name
    = IDENTIFIER_POINTER (DECL_ASSEMBLER_NAME (node->decl));
  bool is_default = is_function_default_version (node->decl);
  bool is_isra = strstr (asm_name, ".isra.") != NULL;
  bool is_target_clones
    = lookup_attribute ("target_clones", DECL_ATTRIBUTES (node->decl));
  bool safe_late_isra_dispatch
    = (!target_clones_table && is_isra && !node->callers);

  if (!DECL_FUNCTION_VERSIONED (node->decl)
      || !v
      || !v->next
      || node->dispatcher_function
      || v->dispatcher_resolver)
    continue;

  /* In the early stage, skip plain target_clones declarations because they
     are still simple and will be expanded later.  In the late stage, also
     dispatch FMV sets rooted at IPA-SRA ISRA clones.  */
  if (early)
    {
      if (is_default && !is_target_clones)
        to_dispatch.safe_push (node);
    }
  else if ((is_default && !is_target_clones) || safe_late_isra_dispatch)
    to_dispatch.safe_push (node);
      }
  else if (!early)
    FOR_EACH_FUNCTION (node)
      {
  cgraph_function_version_info *v = node->function_version ();
  const char *asm_name
    = IDENTIFIER_POINTER (DECL_ASSEMBLER_NAME (node->decl));
  if (!DECL_FUNCTION_VERSIONED (node->decl)
      || !v
      || !v->next
      || node->dispatcher_function
      || v->dispatcher_resolver)
    continue;

  if (is_function_default_version (node->decl)
      || strstr (asm_name, ".isra."))
    to_dispatch.safe_push (node);
      }
  for (unsigned i = 0; i < to_dispatch.length (); i++)
    create_dispatcher_calls (to_dispatch[i]);

  FOR_EACH_FUNCTION (node)
    redirect_to_specific_clone (node);

  /* Sweep all functions and clear gimple modified flags that may have been
     left by prior IPA passes (e.g. IPA-SRA's modify_call).  The IPA_PASS
     execute phases do not run per-function TODO cleanup, so modified stmts
     can persist until a SIMPLE_IPA_PASS triggers verify_ssa.  */
  FOR_EACH_FUNCTION_WITH_GIMPLE_BODY (node)
    {
      function *fn = DECL_STRUCT_FUNCTION (node->decl);
      if (!fn)
	continue;
      basic_block bb;
      FOR_EACH_BB_FN (bb, fn)
	for (gimple_stmt_iterator gsi = gsi_start_bb (bb); !gsi_end_p (gsi);
	     gsi_next (&gsi))
	  {
	    gimple *stmt = gsi_stmt (gsi);
	    if (gimple_modified_p (stmt))
	      update_stmt_fn (fn, stmt);
	  }
    }

  return 0;
}

namespace {

const pass_data pass_data_target_clone =
{
  SIMPLE_IPA_PASS,		/* type */
  "targetclone",		/* name */
  OPTGROUP_NONE,		/* optinfo_flags */
  TV_NONE,			/* tv_id */
  ( PROP_ssa | PROP_cfg ),	/* properties_required */
  0,				/* properties_provided */
  0,				/* properties_destroyed */
  0,				/* todo_flags_start */
  TODO_update_ssa		/* todo_flags_finish */
};

class pass_target_clone : public simple_ipa_opt_pass
{
public:
  pass_target_clone (gcc::context *ctxt)
    : simple_ipa_opt_pass (pass_data_target_clone, ctxt), early_p (false)
  {}
  bool early_p;

  void set_pass_param (unsigned int n, bool param) final override
    {
      gcc_assert (n == 0);
      early_p = param;
    }
  /* opt_pass methods: */
  bool gate (function *) final override;
  opt_pass * clone () final override { return new pass_target_clone (m_ctxt); }
  unsigned int execute (function *) final override
  {
    return ipa_target_clone (early_p);
  }
};

bool
pass_target_clone::gate (function *)
{
  /* If there were any errors avoid pass property verification errors.  */
  return !seen_error ();
}

} // anon namespace

simple_ipa_opt_pass *
make_pass_target_clone (gcc::context *ctxt)
{
  return new pass_target_clone (ctxt);
}

/* packet-dcerpc-samr.c
 * Routines for SMB \\PIPE\\samr packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-samr.c,v 1.10 2002/02/10 23:51:44 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-dcerpc-samr.h"
#include "smb.h"	/* for "NT_errors[]" */

int dissect_nt_sid(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *parent_tree, char *name);

static int proto_dcerpc_samr = -1;

static int hf_samr_hnd = -1;
static int hf_samr_group = -1;
static int hf_samr_rid = -1;
static int hf_samr_type = -1;
static int hf_samr_alias = -1;
static int hf_samr_rid_attrib = -1;
static int hf_samr_rc = -1;
static int hf_samr_index = -1;
static int hf_samr_acct_ctrl = -1;
static int hf_samr_count = -1;

static int hf_samr_level = -1;
static int hf_samr_start_idx = -1;
static int hf_samr_max_entries = -1;
static int hf_samr_entries = -1;
static int hf_samr_pref_maxsize = -1;
static int hf_samr_total_size = -1;
static int hf_samr_ret_size = -1;
static int hf_samr_acct_name = -1;
static int hf_samr_full_name = -1;
static int hf_samr_acct_desc = -1;
static int hf_samr_home = -1;
static int hf_samr_home_drive = -1;
static int hf_samr_script = -1;
static int hf_samr_workstations = -1;
static int hf_samr_profile = -1;
static int hf_samr_server = -1;
static int hf_samr_domain = -1;
static int hf_samr_controller = -1;
static int hf_samr_access = -1;
static int hf_samr_mask = -1;
static int hf_samr_crypt_password = -1;
static int hf_samr_crypt_hash = -1;
static int hf_samr_lm_change = -1;
static int hf_samr_attrib = -1;
static int hf_samr_max_pwd_age = -1;
static int hf_samr_min_pwd_age = -1;
static int hf_samr_min_pwd_len = -1;
static int hf_samr_pwd_history_len = -1;
static int hf_samr_num_users = -1;
static int hf_samr_num_groups = -1;
static int hf_samr_num_aliases = -1;
static int hf_samr_resume_hnd = -1;
static int hf_samr_bad_pwd_count = -1;
static int hf_samr_logon_count = -1;
static int hf_samr_logon_time = -1;
static int hf_samr_logoff_time = -1;
static int hf_samr_kickoff_time = -1;
static int hf_samr_pwd_last_set_time = -1;
static int hf_samr_pwd_can_change_time = -1;
static int hf_samr_pwd_must_change_time = -1;
static int hf_samr_acct_expiry_time = -1;
static int hf_samr_country = -1;
static int hf_samr_codepage = -1;
static int hf_samr_comment = -1;
static int hf_samr_parameters = -1;
static int hf_samr_nt_pwd_set = -1;
static int hf_samr_lm_pwd_set = -1;
static int hf_samr_pwd_expired = -1;
static int hf_samr_revision = -1;
static int hf_samr_divisions = -1;
static int hf_samr_info_type = -1;

static int hf_samr_unknown_hyper = -1;
static int hf_samr_unknown_long = -1;
static int hf_samr_unknown_short = -1;
static int hf_samr_unknown_char = -1;
static int hf_samr_unknown_string = -1;
static int hf_samr_unknown_time = -1;

/* these are used by functions in packet-dcerpc-nt.c */
int hf_nt_str_len = -1;
int hf_nt_str_off = -1;
int hf_nt_str_max_len = -1;
int hf_nt_string_length = -1;
int hf_nt_string_size = -1;

static gint ett_dcerpc_samr = -1;
gint ett_nt_unicode_string = -1;	/* used by packet-dcerpc-nt.c*/
static gint ett_samr_user_dispinfo_1 = -1;

static e_uuid_t uuid_dcerpc_samr = {
        0x12345778, 0x1234, 0xabcd, 
        { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac}
};

static guint16 ver_dcerpc_samr = 1;




/* functions to dissect a UNICODE_STRING structure, common to many 
   NT services
   struct {
     short len;
     short size;
     [size_is(size/2), length_is(len/2), ptr] unsigned short *string;
   } UNICODE_STRING;

   these variables can be found in packet-dcerpc-samr.c 
*/
extern int hf_nt_str_len;
extern int hf_nt_str_off;
extern int hf_nt_str_max_len;
extern int hf_nt_string_length;
extern int hf_nt_string_size;
extern gint ett_nt_unicode_string;

int
dissect_ndr_nt_UNICODE_STRING_string (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
	guint32 len, off, max_len;
	guint16 *data16;
	char *text;
	int old_offset;
	header_field_info *hfi;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_nt_str_len, &len);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_nt_str_off, &off);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_nt_str_max_len, &max_len);

	old_offset=offset;
	offset = prs_uint16s(tvb, offset, pinfo, tree, max_len, &data16, NULL);
	text = fake_unicode(data16, max_len);

	hfi = proto_registrar_get_nth(di->hf_index);
	proto_tree_add_string_format(tree, di->hf_index, 
		tvb, old_offset, offset-old_offset,
		text, "%s: %s", hfi->name, text);

	if(tree){
		proto_item_set_text(tree, "%s: %s", hfi->name, text);
		proto_item_set_text(tree->parent, "%s: %s", hfi->name, text);
	}
  	return offset;
}

int
dissect_ndr_nt_UNICODE_STRING (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree, 
                             char *drep, int hf_index)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"Unicode String");
		tree = proto_item_add_subtree(item, ett_nt_unicode_string);
	}

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_nt_string_length, NULL);
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_nt_string_size, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_UNICODE_STRING_string, NDR_POINTER_PTR,
			hf_index);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

/* functions to dissect a STRING structure, common to many 
   NT services
   struct {
     short len;
     short size;
     [size_is(size), length_is(len), ptr] char *string;
   } STRING;
*/

static int
dissect_ndr_nt_STRING_string (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
	guint32 len, off, max_len;
	guint8 *text;
	int old_offset;
	header_field_info *hfi;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_nt_str_len, &len);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_nt_str_off, &off);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_nt_str_max_len, &max_len);

	old_offset=offset;
	offset = prs_uint8s(tvb, offset, pinfo, tree, max_len, &text, NULL);

	hfi = proto_registrar_get_nth(di->hf_index);
	proto_tree_add_string_format(tree, di->hf_index, 
		tvb, old_offset, offset-old_offset,
		text, "%s: %s", hfi->name, text);

	if(tree){
		proto_item_set_text(tree, "%s: %s", hfi->name, text);
		proto_item_set_text(tree->parent, "%s: %s", hfi->name, text);
	}
  	return offset;
}

int
dissect_ndr_nt_STRING (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree, 
                             char *drep, int hf_index)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"Unicode String");
		tree = proto_item_add_subtree(item, ett_nt_unicode_string);
	}

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_nt_string_length, NULL);
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_nt_string_size, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_STRING_string, NDR_POINTER_PTR,
			hf_index);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

/* This should get fixed both here and in dissect_smb_64bit_time so
   one can handle both BIG and LITTLE endian encodings 
 */
int dissect_smb_64bit_time(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, int hf_date);
int
dissect_ndr_nt_NTTIME (tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree, 
			char *drep, int hf_index)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	/* align to 4 byte boundary */
	if(offset&0x03){
		offset = (offset&0xfffffffc)+4;
	}

	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		 hf_index);
	return offset;
}

static int
samr_dissect_SID(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree, 
			char *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/* just a run to handle conformant arrays, no scalars to dissect */
		return offset;
	}

	/* the SID contains a conformant array, first we must eat
	   the 4-byte max_count before we can hand it off */
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_count, NULL);

	offset = dissect_nt_sid(tvb, pinfo, offset, tree, "Domain");
	return offset;
}

static int
samr_dissect_SID_ptr(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree, 
			char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_SID, NDR_POINTER_UNIQUE,
			-1);
	return offset;
}



/* above this line, just some general support routines which should be placed
   in some more generic file common to all NT services dissectors
*/






static int
samr_dissect_context_handle_reply(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree, 
			char *drep)
{
	offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
			hf_samr_hnd, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_rc, NULL);

	return offset;
}


static int
samr_dissect_open_user_rqst(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree, 
			char *drep)
{
	offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
			hf_samr_hnd, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_access, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_rid, NULL);

	return offset;
}

static int
samr_dissect_pointer_long(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     di->hf_index, NULL);
	return offset;
}

static int
samr_dissect_pointer_STRING(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	offset = dissect_ndr_nt_STRING(tvb, offset, pinfo, tree, drep,
			di->hf_index);
	return offset;
}

static int
samr_dissect_pointer_UNICODE_STRING(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
			di->hf_index);
	return offset;
}

static int
samr_dissect_pointer_short(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     di->hf_index, NULL);
	return offset;
}


static int
samr_dissect_query_dispinfo_rqst (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_start_idx, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_max_entries, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_pref_maxsize, NULL);
        return offset;
}

static int
samr_dissect_USER_DISPINFO_1(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree, 
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"User_DispInfo_1");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				hf_samr_index, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				hf_samr_rid, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				hf_samr_acct_ctrl, NULL);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_name);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_full_name);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_desc);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_DISPINFO_1_ARRAY_users(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree, 
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_DISPINFO_1);

	return offset;
}

static int
samr_dissect_USER_DISPINFO_1_ARRAY (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree, 
                             char *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"User_DispInfo_1 Array");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}


        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_count, &count);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_DISPINFO_1_ARRAY_users, NDR_POINTER_PTR,
			-1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}



static int
samr_dissect_USER_DISPINFO_2(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree, 
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"User_DispInfo_2");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_index, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_rid, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_acct_ctrl, NULL);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_name);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_desc);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_DISPINFO_2_ARRAY_users (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_DISPINFO_2);

	return offset;
}

static int
samr_dissect_USER_DISPINFO_2_ARRAY (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree, 
                             char *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"User_DispInfo_2 Array");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}


        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_count, &count);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_DISPINFO_2_ARRAY_users, NDR_POINTER_PTR,
			-1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}





static int
samr_dissect_GROUP_DISPINFO(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree, 
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"Group_DispInfo");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_index, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_rid, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_acct_ctrl, NULL);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_name);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_desc);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_GROUP_DISPINFO_ARRAY_groups(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree, 
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_GROUP_DISPINFO);

	return offset;
}

static int
samr_dissect_GROUP_DISPINFO_ARRAY(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree, 
			char *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"Group_DispInfo Array");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_count, &count);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_GROUP_DISPINFO_ARRAY_groups, NDR_POINTER_PTR,
			-1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}



static int
samr_dissect_ASCII_DISPINFO(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree, 
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"Ascii_DispInfo");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_index, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_rid, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_acct_ctrl, NULL);
	offset = dissect_ndr_nt_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_name);
	offset = dissect_ndr_nt_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_desc);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_ASCII_DISPINFO_ARRAY_users(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree, 
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_ASCII_DISPINFO);

	return offset;
}

static int
samr_dissect_ASCII_DISPINFO_ARRAY(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"Ascii_DispInfo Array");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_count, &count);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_ASCII_DISPINFO_ARRAY_users, NDR_POINTER_PTR,
			-1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
samr_dissect_DISPLAY_INFO (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree,
                             char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"DispInfo");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, &level);
	switch(level){
	case 1:	
		offset = samr_dissect_USER_DISPINFO_1_ARRAY(
				tvb, offset, pinfo, tree, drep);
		break;
	case 2:	
		offset = samr_dissect_USER_DISPINFO_2_ARRAY(
				tvb, offset, pinfo, tree, drep);
		break;
	case 3:	
		offset = samr_dissect_GROUP_DISPINFO_ARRAY(
				tvb, offset, pinfo, tree, drep);
		break;
	case 4:	
		offset = samr_dissect_ASCII_DISPINFO_ARRAY(
				tvb, offset, pinfo, tree, drep);
		break;
	case 5:	
		offset = samr_dissect_ASCII_DISPINFO_ARRAY(
				tvb, offset, pinfo, tree, drep);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_query_dispinfo_reply (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			hf_samr_total_size);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			hf_samr_ret_size);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_DISPLAY_INFO, NDR_POINTER_REF,
			-1);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rc, NULL);

	return offset;
}


static int
samr_dissect_get_display_enumeration_index_rqst(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, NULL);
	offset = dissect_ndr_nt_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_name);
	return offset;
}


static int
samr_dissect_get_display_enumeration_index_reply(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			hf_samr_index);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rc, NULL);

	return offset;
}




static int
samr_dissect_PASSWORD_INFO(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"Password Info");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_short, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_get_usrdom_pwinfo_reply(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_PASSWORD_INFO, NDR_POINTER_REF,
			-1);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rc, NULL);
	return offset;
}



static int
samr_dissect_connect2_server(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree, 
                             char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"Server");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_nt_UNICODE_STRING_string(tvb, offset, pinfo, 
			tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_connect2_rqst(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_connect2_server, NDR_POINTER_UNIQUE,
			hf_samr_server);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_access, NULL);
	return offset;
}

static int
samr_dissect_connect2_reply(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rc, NULL);
	return offset;
}




static int
samr_dissect_USER_GROUP(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree,
                             char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"User Group");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rid, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rid_attrib, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_GROUP_ARRAY_groups (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_GROUP);

	return offset;
}

static int
samr_dissect_USER_GROUP_ARRAY(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"User_Group Array");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_count, &count);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_GROUP_ARRAY_groups, NDR_POINTER_UNIQUE,
			-1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_GROUP_ARRAY_ptr(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_GROUP_ARRAY, NDR_POINTER_UNIQUE,
			-1);
	return offset;
}

static int
samr_dissect_get_groups_for_user_reply(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_GROUP_ARRAY_ptr, NDR_POINTER_REF,
			-1);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rc, NULL);
	return offset;
}



static int
samr_dissect_open_domain_rqst(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_access, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_SID, NDR_POINTER_REF,
			-1);
	return offset;
}

static int
samr_dissect_open_domain_reply(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rc, NULL);
	return offset;
}



static int
samr_dissect_context_handle_SID(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_SID, NDR_POINTER_REF,
			-1);
	return offset;
}

static int
samr_dissect_context_handle(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
	return offset;
}


static int
samr_dissect_rc(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rc, NULL);
	return offset;
}

static int
samr_dissect_add_member_to_group_rqst(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_group, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rid, NULL);
	return offset;
}

static int
samr_dissect_unknown_3c_reply(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_short, NDR_POINTER_REF,
			hf_samr_unknown_short);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rc, NULL);
	return offset;
}



static int
samr_dissect_create_alias_in_domain_rqst(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_name);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_access, NULL);
	return offset;
}

static int
samr_dissect_create_alias_in_domain_reply(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rid, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rc, NULL);

	return offset;
}


static int
samr_dissect_query_information_alias_rqst(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree, 
			char *drep)
{
	offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
			hf_samr_hnd, NULL);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_samr_level, NULL);

	return offset;
}


static int
samr_dissect_ALIAS_INFO_1 (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, 
		tree, drep,
		hf_samr_acct_name);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rid, NULL);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, 
		tree, drep,
		hf_samr_acct_desc);
	return offset;
}

static int
samr_dissect_ALIAS_INFO(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"AliasInfo");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, &level);
	switch(level){
	case 1:	
		offset = samr_dissect_ALIAS_INFO_1(
				tvb, offset, pinfo, tree, drep);
		break;
	case 2:	
		offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, 
			tree, drep,
			hf_samr_acct_name);
		break;
	case 3:	
		offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, 
			tree, drep,
			hf_samr_acct_desc);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_ALIAS_INFO_ptr(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_ALIAS_INFO, NDR_POINTER_UNIQUE,
			-1);
	return offset;
}

static int
samr_dissect_query_information_alias_reply(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree, 
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_ALIAS_INFO_ptr, NDR_POINTER_REF,
			-1);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_rc, NULL);
	return offset;
}

static int
samr_dissect_set_information_alias_rqst(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_ALIAS_INFO, NDR_POINTER_REF,
			-1);
	return offset;
}


static int
samr_dissect_CRYPT_PASSWORD(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree, 
			char *drep)
{
	proto_tree_add_item(tree, hf_samr_crypt_password, tvb, offset, 516,
		FALSE);
	offset += 516;
	return offset;
}

static int
samr_dissect_CRYPT_HASH(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree, 
			char *drep)
{
	proto_tree_add_item(tree, hf_samr_crypt_hash, tvb, offset, 16,
		FALSE);
	offset += 16;
	return offset;
}


static int
samr_dissect_oem_change_password_user2_rqst(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_STRING, NDR_POINTER_UNIQUE,
			hf_samr_server);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_STRING, NDR_POINTER_REF,
			hf_samr_acct_name);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_CRYPT_PASSWORD, NDR_POINTER_UNIQUE,
			-1);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_CRYPT_HASH, NDR_POINTER_UNIQUE,
			-1);
	return offset;
}

static int
samr_dissect_unicode_change_password_user2_rqst(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_UNICODE_STRING, NDR_POINTER_UNIQUE,
			hf_samr_server);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_UNICODE_STRING, NDR_POINTER_REF,
			hf_samr_acct_name);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_CRYPT_PASSWORD, NDR_POINTER_UNIQUE,
			-1);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_CRYPT_HASH, NDR_POINTER_UNIQUE,
			-1);
        offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_lm_change, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_CRYPT_PASSWORD, NDR_POINTER_UNIQUE,
			-1);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_CRYPT_HASH, NDR_POINTER_UNIQUE,
			-1);
	return offset;
}

static int
samr_dissect_unknown_3b_rqst(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_unknown_short, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_UNICODE_STRING, NDR_POINTER_UNIQUE,
			hf_samr_unknown_string);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_UNICODE_STRING, NDR_POINTER_UNIQUE,
			hf_samr_unknown_string);
	return offset;
}


static int
samr_dissect_create_user2_in_domain_rqst(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree, 
			char *drep)
{
        
	offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
			hf_samr_hnd, NULL);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_name);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_acct_ctrl, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_access, NULL);

	return offset;
}

static int
samr_dissect_create_user2_in_domain_reply(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_unknown_long, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rid, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rc, NULL);
	return offset;
}

static int
samr_dissect_get_display_enumeration_index2_rqst(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, NULL);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_name);
	return offset;
}

static int
samr_dissect_get_display_enumeration_index2_reply(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_index, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rc, NULL);
	return offset;
}

static int
samr_dissect_change_password_user_rqst(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree, 
			char *drep)
{
	offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
			hf_samr_hnd, NULL);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_char, NULL);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_CRYPT_HASH, NDR_POINTER_UNIQUE,
			-1);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_CRYPT_HASH, NDR_POINTER_UNIQUE,
			-1);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_char, NULL);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_CRYPT_HASH, NDR_POINTER_UNIQUE,
			-1);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_CRYPT_HASH, NDR_POINTER_UNIQUE,
			-1);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_char, NULL);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_CRYPT_HASH, NDR_POINTER_UNIQUE,
			-1);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_char, NULL);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_CRYPT_HASH, NDR_POINTER_UNIQUE,
			-1);

	return offset;
}

static int
samr_dissect_set_member_attributes_of_group_rqst(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_attrib, NULL);
	return offset;
}


static int
samr_dissect_GROUP_INFO_1 (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, 
		tree, drep,
		hf_samr_acct_name);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rid, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
					hf_samr_attrib, NULL);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, 
		tree, drep,
		hf_samr_acct_desc);
	return offset;
}

static int
samr_dissect_GROUP_INFO(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"GroupInfo");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, &level);
	switch(level){
	case 1:	
		offset = samr_dissect_GROUP_INFO_1(
				tvb, offset, pinfo, tree, drep);
		break;
	case 2:	
		offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, 
			tree, drep,
			hf_samr_acct_name);
		break;
	case 3:
	        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                        hf_samr_attrib, NULL);
		break;
	case 4:	
		offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, 
			tree, drep,
			hf_samr_acct_desc);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_GROUP_INFO_ptr(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_GROUP_INFO, NDR_POINTER_UNIQUE,
			-1);
	return offset;
}

static int
samr_dissect_query_information_group_rqst (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, NULL);
	return offset;
}

static int
samr_dissect_query_information_group_reply(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_GROUP_INFO_ptr, NDR_POINTER_REF,
			-1);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_rc, NULL);
	return offset;
}

static int
samr_dissect_set_information_group_rqst (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_GROUP_INFO, NDR_POINTER_REF,
			-1);
	return offset;
}



static int
samr_dissect_get_domain_password_information_rqst (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_STRING, NDR_POINTER_UNIQUE,
			hf_samr_domain);
	return offset;
}


static int
samr_dissect_DOMAIN_INFO_1(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree,
                             char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"DomainInfo_1");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
					hf_samr_min_pwd_len, NULL);
        offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
					hf_samr_pwd_history_len, NULL);
        offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
					hf_samr_unknown_long, NULL);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
					hf_samr_max_pwd_age);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
					hf_samr_min_pwd_age);
	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_DOMAIN_INFO_2(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"DomainInfo_2");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_time);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_string);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_domain);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_controller);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_time);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_long, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_long, NULL);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_char, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_num_users, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_num_groups, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_num_aliases, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_DOMAIN_INFO_8(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree,
                             char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"DomainInfo_8");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
					hf_samr_max_pwd_age);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
					hf_samr_min_pwd_age);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_REPLICATION_STATUS(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"Replication Status");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_uint64 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_hyper, NULL);
	offset = dissect_ndr_uint64 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_hyper, NULL);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_short, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_DOMAIN_INFO_11(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree,
                             char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"DomainInfo_11");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = samr_dissect_DOMAIN_INFO_2(
			tvb, offset, pinfo, tree, drep);
	offset = samr_dissect_REPLICATION_STATUS(
			tvb, offset, pinfo, tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_DOMAIN_INFO_13(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree,
                             char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"DomainInfo_13");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
					hf_samr_unknown_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
					hf_samr_unknown_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
					hf_samr_unknown_time);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
samr_dissect_DOMAIN_INFO(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"DomainInfo");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, &level);
	switch(level){
	case 1:	
		offset = samr_dissect_DOMAIN_INFO_1(
				tvb, offset, pinfo, tree, drep);
		break;
	case 2:	
		offset = samr_dissect_DOMAIN_INFO_2(
				tvb, offset, pinfo, tree, drep);
		break;

	case 3:
		offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_unknown_time);
		break;
	case 4:
		offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, 
			tree, drep, hf_samr_unknown_string);
		break;

	case 5:
		offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, 
			tree, drep, hf_samr_domain);
		break;

	case 6:
		offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, 
			tree, drep, hf_samr_controller);
		break;

	case 7:
	        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_short, NULL);
		break;
	case 8:	
		offset = samr_dissect_DOMAIN_INFO_8(
				tvb, offset, pinfo, tree, drep);
		break;
	case 9:
	        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_short, NULL);
		break;
	case 11:	
		offset = samr_dissect_DOMAIN_INFO_11(
				tvb, offset, pinfo, tree, drep);
		break;
	case 12:
		offset = samr_dissect_REPLICATION_STATUS(
				tvb, offset, pinfo, tree, drep);
		break;
	case 13:	
		offset = samr_dissect_DOMAIN_INFO_13(
				tvb, offset, pinfo, tree, drep);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_DOMAIN_INFO_ptr(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_DOMAIN_INFO, NDR_POINTER_UNIQUE,
			hf_samr_domain);
	return offset;
}

static int
samr_dissect_query_information_domain_reply(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_DOMAIN_INFO_ptr, NDR_POINTER_REF,
			hf_samr_domain);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rc, NULL);
	return offset;
}


static int
samr_dissect_set_information_domain_rqst(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, NULL);
	offset = samr_dissect_DOMAIN_INFO(tvb, offset, pinfo, tree, drep);
	return offset;
}



static int
samr_dissect_lookup_domain_rqst(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
    offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                  hf_samr_hnd, NULL);
    offset = dissect_ndr_nt_UNICODE_STRING (tvb, offset, pinfo, tree, drep,
                                            hf_samr_domain);
	return offset;
}

static int
samr_dissect_lookup_domain_reply(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_SID_ptr, NDR_POINTER_REF,
			-1);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rc, NULL);
	return offset;
}

static int
samr_dissect_PSID(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree,
                             char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"SID");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_SID, NDR_POINTER_UNIQUE,
			-1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
samr_dissect_PSID_ARRAY_sids (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_PSID);

	return offset;
}


static int
samr_dissect_PSID_ARRAY(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"SID Array");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_count, &count);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_PSID_ARRAY_sids, NDR_POINTER_UNIQUE,
			-1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_pindex(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree,
                             char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	dcerpc_info *di;

	di=pinfo->private_data;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"SID");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_UNIQUE,
			di->hf_index);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
samr_dissect_INDEX_ARRAY_value (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_pindex);

	return offset;
}


static int
samr_dissect_INDEX_ARRAY(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	dcerpc_info *di;

	di=pinfo->private_data;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"Index Array");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_count, &count);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_INDEX_ARRAY_value, NDR_POINTER_UNIQUE,
			di->hf_index);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
samr_dissect_get_alias_membership_rqst(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_PSID_ARRAY, NDR_POINTER_REF,
			-1);
	return offset;
}

static int
samr_dissect_get_alias_membership_reply(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_INDEX_ARRAY, NDR_POINTER_REF,
			hf_samr_alias);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_rc, NULL);
	return offset;
}


static int
samr_dissect_IDX_AND_NAME(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree,
                             char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	dcerpc_info *di;

	di=pinfo->private_data;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"IDX_AND_NAME");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_index, NULL);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, 
			tree, drep, di->hf_index);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_IDX_AND_NAME_entry (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_IDX_AND_NAME);

	return offset;
}


static int
samr_dissect_IDX_AND_NAME_ARRAY(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	dcerpc_info *di;

	di=pinfo->private_data;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"IDX_AND_NAME Array");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_count, &count);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_IDX_AND_NAME_entry, NDR_POINTER_UNIQUE,
			di->hf_index);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_IDX_AND_NAME_ARRAY_ptr(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_IDX_AND_NAME_ARRAY, NDR_POINTER_UNIQUE,
			hf_samr_domain);
	return offset;
}

static int
samr_dissect_enum_domains_rqst(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
			hf_samr_hnd, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			hf_samr_resume_hnd);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_pref_maxsize, NULL);
	return offset;
}

static int
samr_dissect_enum_domains_reply(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			hf_samr_resume_hnd);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_IDX_AND_NAME_ARRAY_ptr, NDR_POINTER_REF,
			hf_samr_domain);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			hf_samr_entries);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rc, NULL);
	return offset;
}

static int
samr_dissect_enum_dom_groups_rqst(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
			hf_samr_hnd, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			hf_samr_resume_hnd);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_mask, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_pref_maxsize, NULL);
	return offset;
}

static int
samr_dissect_enum_dom_groups_reply(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			hf_samr_resume_hnd);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_IDX_AND_NAME_ARRAY_ptr, NDR_POINTER_REF,
			hf_samr_group);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			hf_samr_entries);
        offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_samr_rc, NULL);
	return offset;
}

static int
samr_dissect_enum_dom_alias_reply(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			hf_samr_resume_hnd);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_IDX_AND_NAME_ARRAY_ptr, NDR_POINTER_REF,
			hf_samr_alias);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			hf_samr_entries);
        offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_samr_rc, NULL);
	return offset;
}

static int
samr_dissect_get_members_in_alias_reply(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_PSID_ARRAY, NDR_POINTER_REF,
			-1);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_LOGON_HOURS_entry(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_char, NULL);
	return offset;
}

static int
samr_dissect_LOGON_HOURS_hours(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree,
                             char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"LOGON_HOURS");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_LOGON_HOURS_entry);

	proto_item_set_len(item, offset-old_offset);
	return offset;

	return offset;
}

static int
samr_dissect_LOGON_HOURS(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"LOGON_HOURS");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
				hf_samr_divisions, NULL);
	/* XXX - is this a bitmask like the "logon hours" field in the
	   Remote API call "NetUserGetInfo()" with an information level
	   of 11? */
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_LOGON_HOURS_hours, NDR_POINTER_UNIQUE,
			-1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
samr_dissect_USER_INFO_1(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"UserInfo_1");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_name);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_full_name);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				hf_samr_acct_ctrl, NULL);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_home);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_script);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_2(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"UserInfo_2");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_name);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_full_name);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
				hf_samr_bad_pwd_count, NULL);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
				hf_samr_logon_count, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_3(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"UserInfo_3");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_name);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_full_name);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				hf_samr_rid, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				hf_samr_group, NULL);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_home);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_home_drive);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_script);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_desc);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_workstations);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_logon_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_logoff_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_pwd_last_set_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_pwd_can_change_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_pwd_must_change_time);
	offset = samr_dissect_LOGON_HOURS(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
				hf_samr_logon_count, NULL);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
				hf_samr_bad_pwd_count, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				hf_samr_acct_ctrl, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_5(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"UserInfo_5");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_name);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_full_name);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				hf_samr_rid, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				hf_samr_group, NULL);
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
				hf_samr_country, NULL);
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
				hf_samr_codepage, NULL);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_home);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_home_drive);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_script);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_desc);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_workstations);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_logon_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_logoff_time);
	offset = samr_dissect_LOGON_HOURS(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
				hf_samr_bad_pwd_count, NULL);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
				hf_samr_logon_count, NULL);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_pwd_last_set_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_expiry_time);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				hf_samr_acct_ctrl, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_6(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"UserInfo_6");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_name);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_full_name);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_18(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"UserInfo_18");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = samr_dissect_CRYPT_HASH(tvb, offset, pinfo, tree, drep);
	offset = samr_dissect_CRYPT_HASH(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_char, NULL);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_char, NULL);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_char, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_19(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"UserInfo_19");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				hf_samr_acct_ctrl, NULL);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_logon_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_logoff_time);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
				hf_samr_bad_pwd_count, NULL);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
				hf_samr_logon_count, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_BUFFER_entry(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_char, NULL);
	return offset;
}


static int
samr_dissect_BUFFER_buffer(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree,
                             char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"BUFFER");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_BUFFER_entry);

	proto_item_set_len(item, offset-old_offset);
	return offset;

	return offset;
}

static int
samr_dissect_BUFFER(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"BUFFER");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				hf_samr_count, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_BUFFER_buffer, NDR_POINTER_UNIQUE,
			-1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_BUFFER_ptr(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_BUFFER, NDR_POINTER_UNIQUE,
			-1);
	return offset;
}

static int
samr_dissect_USER_INFO_21(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"UserInfo_21");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_logon_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_logoff_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_kickoff_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_pwd_last_set_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_pwd_can_change_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_pwd_must_change_time);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_name);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_full_name);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_home);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_home_drive);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_script);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_profile);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_desc);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_workstations);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_comment);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_parameters);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_unknown_string);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_unknown_string);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_unknown_string);
	offset = samr_dissect_BUFFER(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				hf_samr_rid, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				hf_samr_group, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				hf_samr_acct_ctrl, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				hf_samr_unknown_long, NULL);
	offset = samr_dissect_LOGON_HOURS(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
				hf_samr_bad_pwd_count, NULL);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
				hf_samr_logon_count, NULL);
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
				hf_samr_country, NULL);
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
				hf_samr_codepage, NULL);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
				hf_samr_nt_pwd_set, NULL);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
				hf_samr_lm_pwd_set, NULL);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
				hf_samr_pwd_expired, NULL);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
				hf_samr_unknown_char, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_22(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"UserInfo_22");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = samr_dissect_USER_INFO_21(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_uint64 (tvb, offset, pinfo, tree, drep,
			hf_samr_revision, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_23(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"UserInfo_23");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = samr_dissect_USER_INFO_21(tvb, offset, pinfo, tree, drep);
	offset = samr_dissect_CRYPT_PASSWORD(tvb, offset, pinfo, tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_24(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"UserInfo_24");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = samr_dissect_CRYPT_PASSWORD(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
				hf_samr_unknown_char, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree,
                             char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"UserInfo");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, &level);

	switch(level){
	case 1:	
		offset = samr_dissect_USER_INFO_1(
				tvb, offset, pinfo, tree, drep);
		break;
	case 2:	
		offset = samr_dissect_USER_INFO_2(
				tvb, offset, pinfo, tree, drep);
		break;
	case 3:	
		offset = samr_dissect_USER_INFO_3(
				tvb, offset, pinfo, tree, drep);
		break;
	case 4:	
		offset = samr_dissect_LOGON_HOURS(
				tvb, offset, pinfo, tree, drep);
		break;
	case 5:	
		offset = samr_dissect_USER_INFO_5(
				tvb, offset, pinfo, tree, drep);
		break;
	case 6:	
		offset = samr_dissect_USER_INFO_6(
				tvb, offset, pinfo, tree, drep);
		break;
	case 7:
		offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_full_name);
		break;
	case 8:
		offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_desc);
		break;
	case 9:
	        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
        	                             hf_samr_unknown_long, NULL);
		break;
	case 10:	
		offset = samr_dissect_USER_INFO_6(
				tvb, offset, pinfo, tree, drep);
		break;
	case 11:
		offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_home);
		break;
	case 12:
		offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_home_drive);
		break;
	case 13:
		offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_script);
		break;
	case 14:
		offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_workstations);
		break;
	case 16:
	        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
        	                             hf_samr_unknown_long, NULL);
		break;
	case 17:
		offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
					hf_samr_unknown_time);
		break;
	case 18:	
		offset = samr_dissect_USER_INFO_18(
				tvb, offset, pinfo, tree, drep);
		break;
	case 19:	
		offset = samr_dissect_USER_INFO_19(
				tvb, offset, pinfo, tree, drep);
		break;
	case 20:
		offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_profile);
		break;
	case 21:	
		offset = samr_dissect_USER_INFO_21(
				tvb, offset, pinfo, tree, drep);
		break;
	case 22:	
		offset = samr_dissect_USER_INFO_22(
				tvb, offset, pinfo, tree, drep);
		break;
	case 23:	
		offset = samr_dissect_USER_INFO_23(
				tvb, offset, pinfo, tree, drep);
		break;
	case 24:	
		offset = samr_dissect_USER_INFO_24(
				tvb, offset, pinfo, tree, drep);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_ptr(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_INFO, NDR_POINTER_UNIQUE,
			-1);
	return offset;
}

static int
samr_dissect_set_information_user2_rqst(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
			hf_samr_hnd, NULL);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_samr_level, NULL);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_INFO, NDR_POINTER_REF,
			-1);

	return offset;
}

static int
samr_dissect_query_userinfo_reply(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_INFO_ptr, NDR_POINTER_REF,
			-1);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_MEMBER_ARRAY_type(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				hf_samr_type, NULL);

	return offset;
}


static int
samr_dissect_MEMBER_ARRAY_types(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"Types");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_MEMBER_ARRAY_type);

	proto_item_set_len(item, offset-old_offset);
	return offset;

	return offset;
}

static int
samr_dissect_MEMBER_ARRAY_rid(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				hf_samr_rid, NULL);

	return offset;
}


static int
samr_dissect_MEMBER_ARRAY_rids(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"RIDs");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_MEMBER_ARRAY_rid);

	proto_item_set_len(item, offset-old_offset);
	return offset;

	return offset;
}

static int
samr_dissect_MEMBER_ARRAY(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"Member Array");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_samr_count, &count);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_MEMBER_ARRAY_rids, NDR_POINTER_UNIQUE,
			-1);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_MEMBER_ARRAY_types, NDR_POINTER_UNIQUE,
			-1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_MEMBER_ARRAY_ptr(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_MEMBER_ARRAY, NDR_POINTER_UNIQUE,
			-1);
	return offset;
}

static int
samr_dissect_query_groupmem_reply(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_MEMBER_ARRAY_ptr, NDR_POINTER_REF,
			-1);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_set_sec_object_rqst(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
			hf_samr_hnd, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_info_type, NULL);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_BUFFER, NDR_POINTER_REF,
			-1);

	return offset;
}

static int
samr_dissect_query_sec_object_rqst(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
			hf_samr_hnd, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_info_type, NULL);

	return offset;
}

static int
samr_dissect_query_sec_object_reply(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_BUFFER_ptr, NDR_POINTER_REF,
			-1);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_samr_rc, NULL);


	return offset;
}

static int
samr_dissect_LOOKUP_NAMES_name(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_name);
	return offset;
}

static int
samr_dissect_LOOKUP_NAMES(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"Names");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_LOOKUP_NAMES_name);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
samr_dissect_lookup_names_rqst(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
			hf_samr_hnd, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_samr_count, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_LOOKUP_NAMES, NDR_POINTER_REF,
			-1);

	return offset;
}

static int
samr_dissect_lookup_names_reply(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_INDEX_ARRAY, NDR_POINTER_REF,
			hf_samr_rid);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_INDEX_ARRAY, NDR_POINTER_REF,
			hf_samr_type);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_LOOKUP_RIDS_rid(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				hf_samr_rid, NULL);

	return offset;
}

static int
samr_dissect_LOOKUP_RIDS(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"RIDs");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_LOOKUP_RIDS_rid);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
samr_dissect_lookup_rids_rqst(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
			hf_samr_hnd, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_samr_count, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_LOOKUP_RIDS, NDR_POINTER_REF,
			-1);

	return offset;
}

static int
samr_dissect_UNICODE_STRING_ARRAY_name(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_name);
	return offset;
}

static int
samr_dissect_UNICODE_STRING_ARRAY(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"Names");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_samr_count, NULL);

	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_UNICODE_STRING_ARRAY_name);

	proto_item_set_len(item, offset-old_offset);
	return offset;

	return offset;
}


static int
samr_dissect_lookup_rids_reply(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_UNICODE_STRING_ARRAY, NDR_POINTER_REF,
			hf_samr_rid);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_MEMBER_ARRAY_types, NDR_POINTER_REF,
			-1);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_samr_rc, NULL);

	return offset;
}



static dcerpc_sub_dissector dcerpc_samr_dissectors[] = {
        { SAMR_CONNECT_ANON, "CONNECT_ANON",
		samr_dissect_connect2_rqst,
		samr_dissect_context_handle_reply },
        { SAMR_CLOSE_HND, "CLOSE_HND",
		samr_dissect_context_handle,
		samr_dissect_context_handle_reply },
        { SAMR_SET_SEC_OBJECT, "SET_SEC_OBJECT",
		samr_dissect_set_sec_object_rqst,
		samr_dissect_rc },
        { SAMR_QUERY_SEC_OBJECT, "QUERY_SEC_OBJECT", 
		samr_dissect_query_sec_object_rqst,
		samr_dissect_query_sec_object_reply },
        { SAMR_SHUTDOWN_SAM_SERVER, "SHUTDOWN_SAM_SERVER",
		samr_dissect_context_handle,
		samr_dissect_rc },
        { SAMR_LOOKUP_DOMAIN, "LOOKUP_DOMAIN",
		samr_dissect_lookup_domain_rqst,
		samr_dissect_lookup_domain_reply },
        { SAMR_ENUM_DOMAINS, "ENUM_DOMAINS",
		samr_dissect_enum_domains_rqst,
		samr_dissect_enum_domains_reply },
        { SAMR_OPEN_DOMAIN, "OPEN_DOMAIN",
		samr_dissect_open_domain_rqst,
		samr_dissect_open_domain_reply },
	{ SAMR_QUERY_DOMAIN_INFO, "QUERY_INFORMATION_DOMAIN",
		samr_dissect_query_information_alias_rqst,
		samr_dissect_query_information_domain_reply },
        { SAMR_SET_DOMAIN_INFO, "SET_INFORMATION_DOMAIN",
		samr_dissect_set_information_domain_rqst,
		samr_dissect_rc },
        { SAMR_CREATE_DOM_GROUP, "CREATE_GROUP_IN_DOMAIN",
		samr_dissect_create_alias_in_domain_rqst,
		samr_dissect_create_alias_in_domain_reply },
        { SAMR_ENUM_DOM_GROUPS, "ENUM_DOM_GROUPS",
		samr_dissect_enum_dom_groups_rqst,
		samr_dissect_enum_dom_groups_reply },
	{ SAMR_CREATE_USER_IN_DOMAIN, "CREATE_USER_IN_DOMAIN",
		samr_dissect_create_alias_in_domain_rqst,
		samr_dissect_create_alias_in_domain_reply },
        { SAMR_ENUM_DOM_USERS, "ENUM_DOM_USERS",
		samr_dissect_enum_dom_groups_rqst,
		samr_dissect_enum_dom_groups_reply },
        { SAMR_CREATE_DOM_ALIAS, "CREATE_ALIAS_IN_DOMAIN",
		samr_dissect_create_alias_in_domain_rqst,
		samr_dissect_create_alias_in_domain_reply },
        { SAMR_ENUM_DOM_ALIASES, "ENUM_DOM_ALIASES",
		samr_dissect_enum_dom_groups_rqst,
		samr_dissect_enum_dom_alias_reply },
        { SAMR_GET_ALIAS_MEMBERSHIP, "GET_ALIAS_MEMBERSHIP",
		samr_dissect_get_alias_membership_rqst,
		samr_dissect_get_alias_membership_reply },
        { SAMR_LOOKUP_NAMES, "LOOKUP_NAMES", 
		samr_dissect_lookup_names_rqst,
		samr_dissect_lookup_names_reply },
        { SAMR_LOOKUP_RIDS, "LOOKUP_RIDS",
		samr_dissect_lookup_rids_rqst,
		samr_dissect_lookup_rids_reply },
        { SAMR_OPEN_GROUP, "OPEN_GROUP",
		samr_dissect_open_user_rqst,
		samr_dissect_context_handle_reply },
        { SAMR_QUERY_GROUPINFO, "QUERY_INFORMATION_GROUP",
		samr_dissect_query_information_group_rqst,
		samr_dissect_query_information_group_reply },
        { SAMR_SET_GROUPINFO, "SET_INFORMATION_GROUP",
		samr_dissect_set_information_group_rqst,
		samr_dissect_rc },
        { SAMR_ADD_GROUPMEM, "ADD_MEMBER_TO_GROUP",
		samr_dissect_add_member_to_group_rqst,
		samr_dissect_rc },
        { SAMR_DELETE_DOM_GROUP, "DELETE_DOM_GROUP",
		samr_dissect_context_handle,
		samr_dissect_rc },
        { SAMR_DEL_GROUPMEM, "REMOVE_MEMBER_FROM_GROUP",
		samr_dissect_add_member_to_group_rqst,
		samr_dissect_rc },
        { SAMR_QUERY_GROUPMEM, "QUERY_GROUPMEM",
		samr_dissect_context_handle,
		samr_dissect_query_groupmem_reply },
        { SAMR_SET_MEMBER_ATTRIBUTES_OF_GROUP, "SET_MEMBER_ATTRIBUTES_OF_GROUP",
		samr_dissect_set_member_attributes_of_group_rqst,
		samr_dissect_rc },
        { SAMR_OPEN_ALIAS, "OPEN_ALIAS",
		samr_dissect_open_user_rqst,
		samr_dissect_context_handle_reply },
        { SAMR_QUERY_ALIASINFO, "QUERY_INFORMATION_ALIAS",
		samr_dissect_query_information_alias_rqst,
		samr_dissect_query_information_alias_reply },
        { SAMR_SET_ALIASINFO, "SET_INFORMATION_ALIAS",
		samr_dissect_set_information_alias_rqst,
		samr_dissect_rc },
        { SAMR_DELETE_DOM_ALIAS, "DELETE_DOM_ALIAS",
		samr_dissect_context_handle,
		samr_dissect_rc },
        { SAMR_ADD_ALIASMEM, "ADD_MEMBER_TO_ALIAS",
		samr_dissect_context_handle_SID,
		samr_dissect_rc },
        { SAMR_DEL_ALIASMEM, "REMOVE_MEMBER_FROM_ALIAS",
		samr_dissect_context_handle_SID,
		samr_dissect_rc },
        { SAMR_GET_MEMBERS_IN_ALIAS, "GET_MEMBERS_IN_ALIAS",
		samr_dissect_context_handle,
		samr_dissect_get_members_in_alias_reply },
        { SAMR_OPEN_USER, "OPEN_USER", 
		samr_dissect_open_user_rqst, 
		samr_dissect_context_handle_reply },
        { SAMR_DELETE_DOM_USER, "DELETE_DOM_USER",
		samr_dissect_context_handle,
		samr_dissect_rc },
        { SAMR_QUERY_USERINFO, "QUERY_USERINFO",
		samr_dissect_query_information_alias_rqst,
		samr_dissect_query_userinfo_reply },
        { SAMR_SET_USERINFO2, "SET_USERINFO2",
		samr_dissect_set_information_user2_rqst,
		samr_dissect_rc },
	{ SAMR_CHANGE_PASSWORD_USER, "CHANGE_PASSWORD_USER",
		samr_dissect_change_password_user_rqst,
		samr_dissect_rc },
        { SAMR_GET_GROUPS_FOR_USER, "GET_GROUPS_FOR_USER",
		samr_dissect_context_handle,
		samr_dissect_get_groups_for_user_reply },
        { SAMR_QUERY_DISPINFO, "QUERY_DISPINFO", 
		samr_dissect_query_dispinfo_rqst, 
		samr_dissect_query_dispinfo_reply },
        { SAMR_GET_DISPLAY_ENUMERATION_INDEX, "GET_DISPLAY_ENUMERATION_INDEX", 
		samr_dissect_get_display_enumeration_index_rqst, 
		samr_dissect_get_display_enumeration_index_reply },
        { SAMR_TEST_PRIVATE_FUNCTIONS_DOMAIN, "TEST_PRIVATE_FUNCTIONS_DOMAIN",
		samr_dissect_context_handle,
		samr_dissect_rc },
        { SAMR_TEST_PRIVATE_FUNCTIONS_USER, "TEST_PRIVATE_FUNCTIONS_USER",
		samr_dissect_context_handle,
		samr_dissect_rc },
        { SAMR_GET_USRDOM_PWINFO, "GET_USRDOM_PWINFO",
		samr_dissect_context_handle,
		samr_dissect_get_usrdom_pwinfo_reply },
        { SAMR_REMOVE_MEMBER_FROM_FOREIGN_DOMAIN, "REMOVE_MEMBER_FROM_FOREIGN_DOMAIN",
		samr_dissect_context_handle_SID,
		samr_dissect_rc },
        { SAMR_QUERY_INFORMATION_DOMAIN2, "QUERY_INFORMATION_DOMAIN2",
		samr_dissect_query_information_alias_rqst,
		samr_dissect_query_information_domain_reply },
        { SAMR_UNKNOWN_2f, "UNKNOWN_2f",
		samr_dissect_query_information_alias_rqst,
		samr_dissect_query_userinfo_reply },
        { SAMR_QUERY_DISPINFO2, "QUERY_INFORMATION_DISPLAY2",
		samr_dissect_query_dispinfo_rqst,
		samr_dissect_query_dispinfo_reply },
        { SAMR_GET_DISPLAY_ENUMERATION_INDEX2, "GET_DISPLAY_ENUMERATION_INDEX2",
		samr_dissect_get_display_enumeration_index2_rqst,
		samr_dissect_get_display_enumeration_index2_reply },
        { SAMR_CREATE_USER2_IN_DOMAIN, "CREATE_USER2_IN_DOMAIN",
		samr_dissect_create_user2_in_domain_rqst,
		samr_dissect_create_user2_in_domain_reply },
        { SAMR_QUERY_DISPINFO3, "QUERY_INFORMATION_DISPLAY3",
		samr_dissect_query_dispinfo_rqst,
		samr_dissect_query_dispinfo_reply },
        { SAMR_ADD_MULTIPLE_MEMBERS_TO_ALIAS, "ADD_MULTIPLE_MEMBERS_TO_ALIAS",
		samr_dissect_get_alias_membership_rqst,
		samr_dissect_rc },
        { SAMR_REMOVE_MULTIPLE_MEMBERS_FROM_ALIAS, "REMOVE_MULTIPLE_MEMBERS_FROM_ALIAS",
		samr_dissect_get_alias_membership_rqst,
		samr_dissect_rc },
        { SAMR_OEM_CHANGE_PASSWORD_USER2, "OEM_CHANGE_PASSWORD_USER2",
		samr_dissect_oem_change_password_user2_rqst,
		samr_dissect_rc },
        { SAMR_UNICODE_CHANGE_PASSWORD_USER2, "UNICODE_CHANGE_PASSWORD_USER2",
		samr_dissect_unicode_change_password_user2_rqst,
		samr_dissect_rc },
        { SAMR_GET_DOM_PWINFO, "GET_DOMAIN_PASSWORD_INFORMATION",
		samr_dissect_get_domain_password_information_rqst,
		samr_dissect_get_usrdom_pwinfo_reply },
       { SAMR_CONNECT2, "CONNECT2", 
		samr_dissect_connect2_rqst,
		samr_dissect_connect2_reply },
        { SAMR_SET_USERINFO, "SET_USERINFO",
		samr_dissect_set_information_user2_rqst,
		samr_dissect_rc },
        { SAMR_UNKNOWN_3B, "UNKNOWN_3B",
		samr_dissect_unknown_3b_rqst,
		samr_dissect_rc },
        { SAMR_UNKNOWN_3C, "SAMR_UNKNOWN_3C", 
		samr_dissect_context_handle,
		samr_dissect_unknown_3c_reply },
        {0, NULL, NULL,  NULL },
};

void 
proto_register_dcerpc_samr(void)
{
        static hf_register_info hf[] = {
                { &hf_samr_hnd,
                  { "Context Handle", "samr.hnd", FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }},
                { &hf_samr_group,
                  { "Group", "samr.group", FT_UINT32, BASE_DEC, NULL, 0x0, "Group", HFILL }},
                { &hf_samr_rid,
                  { "Rid", "samr.rid", FT_UINT32, BASE_DEC, NULL, 0x0, "RID", HFILL }},
                { &hf_samr_type,
                  { "Type", "samr.type", FT_UINT32, BASE_HEX, NULL, 0x0, "Type", HFILL }},
                { &hf_samr_alias,
                  { "Alias", "samr.alias", FT_UINT32, BASE_HEX, NULL, 0x0, "Alias", HFILL }},
                { &hf_samr_rid_attrib,
                  { "Rid Attrib", "samr.rid.attrib", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
                { &hf_samr_attrib,
                  { "Attributes", "samr.attr", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
                { &hf_samr_rc,
                  { "Return code", "samr.rc", FT_UINT32, BASE_HEX, VALS (NT_errors), 0x0, "", HFILL }},

	{ &hf_samr_level,
		{ "Level", "samr.level", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Level requested/returned for Information", HFILL }},
	{ &hf_samr_start_idx,
		{ "Start Idx", "samr.start_idx", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Start Index for returned Information", HFILL }},

	{ &hf_samr_entries,
		{ "Entries", "samr.entries", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Number of entries to return", HFILL }},

	{ &hf_samr_max_entries,
		{ "Max Entries", "samr.max_entries", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Maximum number of entries", HFILL }},

	{ &hf_samr_pref_maxsize,
		{ "Pref MaxSize", "samr.pref_maxsize", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Maximum Size of data to return", HFILL }},

	{ &hf_samr_total_size,
		{ "Total Size", "samr.total_size", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Total size of data", HFILL }},

	{ &hf_samr_bad_pwd_count,
		{ "Bad Pwd Count", "samr.bad_pwd_count", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Number of bad pwd entries for this user", HFILL }},

	{ &hf_samr_logon_count,
		{ "Logon Count", "samr.logon_count", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Number of logons for this user", HFILL }},

	{ &hf_samr_ret_size,
		{ "Returned Size", "samr.ret_size", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Number of returned objects in this PDU", HFILL }},

	{ &hf_samr_index,
		{ "Index", "samr.index", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Index", HFILL }},

	{ &hf_samr_acct_ctrl,
		{ "Acct Ctrl", "samr.acct_ctrl", FT_UINT32, BASE_HEX, 
		NULL, 0x0, "Acct CTRL", HFILL }},

        { &hf_samr_count,
          { "Count", "samr.count", FT_UINT32, BASE_DEC, NULL, 0x0, "Number of elements in following array", HFILL }},

	{ &hf_samr_acct_name,
		{ "Account Name", "samr.acct_name", FT_STRING, BASE_NONE,
		NULL, 0, "Name of Account", HFILL }},

	{ &hf_samr_server,
		{ "Server", "samr.server", FT_STRING, BASE_NONE,
		NULL, 0, "Name of Server", HFILL }},

	{ &hf_samr_domain,
		{ "Domain", "samr.domain", FT_STRING, BASE_NONE,
		NULL, 0, "Name of Domain", HFILL }},

	{ &hf_samr_controller,
		{ "DC", "samr.dc", FT_STRING, BASE_NONE,
		NULL, 0, "Name of Domain Controller", HFILL }},

	{ &hf_samr_full_name,
		{ "Full Name", "samr.full_name", FT_STRING, BASE_NONE,
		NULL, 0, "Full Name of Account", HFILL }},

	{ &hf_samr_home,
		{ "Home", "samr.home", FT_STRING, BASE_NONE,
		NULL, 0, "Home directory for this user", HFILL }},

	{ &hf_samr_home_drive,
		{ "Home Drive", "samr.home_drive", FT_STRING, BASE_NONE,
		NULL, 0, "Home drive for this user", HFILL }},

	{ &hf_samr_script,
		{ "Script", "samr.script", FT_STRING, BASE_NONE,
		NULL, 0, "Login script for this user", HFILL }},

	{ &hf_samr_workstations,
		{ "Workstations", "samr.workstations", FT_STRING, BASE_NONE,
		NULL, 0, "", HFILL }},

	{ &hf_samr_profile,
		{ "Profile", "samr.profile", FT_STRING, BASE_NONE,
		NULL, 0, "Profile for this user", HFILL }},

	{ &hf_samr_acct_desc,
		{ "Account Desc", "samr.acct_desc", FT_STRING, BASE_NONE,
		NULL, 0, "Account Description", HFILL }},

	{ &hf_samr_comment,
		{ "Comment", "samr.comment", FT_STRING, BASE_NONE,
		NULL, 0, "Comment", HFILL }},

	{ &hf_samr_parameters,
		{ "Parameters", "samr.parameters", FT_STRING, BASE_NONE,
		NULL, 0, "Parameters", HFILL }},

	{ &hf_samr_unknown_string,
		{ "Unknwon string", "samr.unknown_string", FT_STRING, BASE_NONE,
		NULL, 0, "Unknown string. If you know what this is, contact ethereal developers.", HFILL }},

	{ &hf_samr_unknown_hyper,
		{ "Unknown hyper", "samr.unknown.hyper", FT_UINT64, BASE_HEX, 
		NULL, 0x0, "Unknown hyper. If you know what this is, contact ethereal developers.", HFILL }},
	{ &hf_samr_unknown_long,
		{ "Unknown long", "samr.unknown.long", FT_UINT32, BASE_HEX, 
		NULL, 0x0, "Unknown long. If you know what this is, contact ethereal developers.", HFILL }},

	{ &hf_samr_unknown_short,
		{ "Unknown short", "samr.unknown.short", FT_UINT16, BASE_HEX, 
		NULL, 0x0, "Unknown short. If you know what this is, contact ethereal developers.", HFILL }},

	{ &hf_samr_unknown_char,
		{ "Unknown char", "samr.unknown.char", FT_UINT8, BASE_HEX, 
		NULL, 0x0, "Unknown char. If you know what this is, contact ethereal developers.", HFILL }},

 	{ &hf_samr_revision,
 		{ "Revision", "samr.revision", FT_UINT64, BASE_HEX, 
 		NULL, 0x0, "Revision number for this structure", HFILL }},
 
 	{ &hf_samr_nt_pwd_set,
 		{ "NT Pwd Set", "samr.nt_pwd_set", FT_UINT8, BASE_HEX, 
 		NULL, 0x0, "Flag indicating whether the NT password has been set", HFILL }},
 
 	{ &hf_samr_lm_pwd_set,
 		{ "LM Pwd Set", "samr.lm_pwd_set", FT_UINT8, BASE_HEX, 
 		NULL, 0x0, "Flag indicating whether the LanManager password has been set", HFILL }},
 
 	{ &hf_samr_pwd_expired,
 		{ "Expired flag", "samr.pwd_Expired", FT_UINT8, BASE_HEX, 
 		NULL, 0x0, "Flag indicating if the password for this account has expired or not", HFILL }},

	/* XXX - is this a standard NT access mask? */
	{ &hf_samr_access,
		{ "Access Mask", "samr.access", FT_UINT32, BASE_HEX, 
		NULL, 0x0, "Access", HFILL }},

	{ &hf_samr_mask,
		{ "Mask", "samr.mask", FT_UINT32, BASE_HEX, 
		NULL, 0x0, "Mask", HFILL }},

	{ &hf_samr_crypt_password, {
		"Password", "samr.crypt_password", FT_BYTES, BASE_HEX,
		NULL, 0, "Encrypted Password", HFILL }},

	{ &hf_samr_crypt_hash, {
		"Hash", "samr.crypt_hash", FT_BYTES, BASE_HEX,
		NULL, 0, "Encrypted Hash", HFILL }},

	{ &hf_samr_lm_change, {
		"LM Change", "samr.lm_change", FT_UINT8, BASE_HEX,
		NULL, 0, "LM Change value", HFILL }},

	{ &hf_samr_max_pwd_age,
		{ "Max Pwd Age", "samr.max_pwd_age", FT_RELATIVE_TIME, BASE_NONE,
		NULL, 0, "Maximum Password Age before it expires", HFILL }},

	{ &hf_samr_min_pwd_age,
		{ "Min Pwd Age", "samr.min_pwd_age", FT_RELATIVE_TIME, BASE_NONE,
		NULL, 0, "Minimum Password Age before it can be changed", HFILL }},
	{ &hf_samr_unknown_time,
		{ "Unknown time", "samr.unknown_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Unknown NT TIME, contact ethereal developers if you know what this is", HFILL }},
	{ &hf_samr_logon_time,
		{ "Logon Time", "samr.logon_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time for last time this user logged on", HFILL }},
	{ &hf_samr_kickoff_time,
		{ "Kickoff Time", "samr.kickoff_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time when this user will be kicked off", HFILL }},
	{ &hf_samr_logoff_time,
		{ "Logoff Time", "samr.logoff_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time for last time this user logged off", HFILL }},
	{ &hf_samr_pwd_last_set_time,
		{ "PWD Last Set", "samr.pwd_last_set_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Last time this users password was changed", HFILL }},
	{ &hf_samr_pwd_can_change_time,
		{ "PWD Can Change", "samr.pwd_can_change_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "When this users password may be changed", HFILL }},
	{ &hf_samr_pwd_must_change_time,
		{ "PWD Must Change", "samr.pwd_must_change_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "When this users password must be changed", HFILL }},
	{ &hf_samr_acct_expiry_time,
		{ "Acct Expiry", "samr.acct_expiry_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "When this user account expires", HFILL }},

	{ &hf_samr_min_pwd_len, {
		"Min Pwd Len", "samr.min_pwd_len", FT_UINT16, BASE_DEC,
		NULL, 0, "Minimum Password Length", HFILL }},
	{ &hf_samr_pwd_history_len, {
		"Pwd History Len", "samr.pwd_history_len", FT_UINT16, BASE_DEC,
		NULL, 0, "Password History Length", HFILL }},
	{ &hf_samr_num_users, {
		"Num Users", "samr.num_users", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of users in this domain", HFILL }},
	{ &hf_samr_num_groups, {
		"Num Groups", "samr.num_groups", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of groups in this domain", HFILL }},
	{ &hf_samr_num_aliases, {
		"Num Aliases", "samr.num_aliases", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of aliases in this domain", HFILL }},
	{ &hf_samr_info_type, {
		"Info Type", "samr.info_type", FT_UINT32, BASE_DEC,
		NULL, 0, "Information Type", HFILL }},
	{ &hf_samr_resume_hnd, {
		"Resume Hnd", "samr.resume_hnd", FT_UINT32, BASE_DEC,
		NULL, 0, "Resume handle", HFILL }},
	{ &hf_samr_country, {
		"Country", "samr.country", FT_UINT16, BASE_DEC,
		NULL, 0, "Country setting for this user", HFILL }},
	{ &hf_samr_codepage, {
		"Codepage", "samr.codepage", FT_UINT16, BASE_DEC,
		NULL, 0, "Codepage setting for this user", HFILL }},
	{ &hf_samr_divisions, {
		"Divisions", "samr.divisions", FT_UINT16, BASE_DEC,
		NULL, 0, "Number of divisions for LOGON_HOURS", HFILL }},


	/* these are used by packet-dcerpc-nt.c */
	{ &hf_nt_string_length,
		{ "Length", "nt.string.length", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Length of string in bytes", HFILL }},

	{ &hf_nt_string_size,
		{ "Size", "nt.string.size", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Size of string in bytes", HFILL }},

	{ &hf_nt_str_len,
		{ "Length", "nt.str.len", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Length of string in short integers", HFILL }},

	{ &hf_nt_str_off,
		{ "Offset", "nt.str.offset", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Offset into string in short integers", HFILL }},

	{ &hf_nt_str_max_len,
		{ "Max Length", "nt.str.max_len", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Max Length of string in short integers", HFILL }},
        };
        static gint *ett[] = {
                &ett_dcerpc_samr,
                &ett_nt_unicode_string,
		&ett_samr_user_dispinfo_1,
        };

        proto_dcerpc_samr = proto_register_protocol(
                "Microsoft Security Account Manager", "SAMR", "samr");

        proto_register_field_array (proto_dcerpc_samr, hf, array_length (hf));
        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_samr(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_samr, ett_dcerpc_samr, &uuid_dcerpc_samr,
                         ver_dcerpc_samr, dcerpc_samr_dissectors);
}

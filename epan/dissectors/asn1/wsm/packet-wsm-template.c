/* packet-wsm.c
 * Routines for IEEE Std 1609.3 WSM packet dissection
 * Copyright 2017, Wayties Inc. Steve Kwon <steve@wayties.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/proto_data.h>
#include <epan/etypes.h>

#include <wsutil/str_util.h>

#include "packet-per.h"
#include "packet-wsm.h"

#define PNAME  "IEEE 1609.3 - WAVE Short Message"
#define PSNAME "WSM"
#define PFNAME "wsm"

static int proto_wsm = -1;

static guint32 extensionId = -1;
static tvbuff_t *data_tvb = NULL;

static int
dissect_wsm_TXpower80211(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int
dissect_wsm_ChannelNumber80211(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int
dissect_wsm_DataRate80211(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

#include "packet-wsm-hf.c"

static int ett_wsm = -1;

#include "packet-wsm-ett.c"
#include "packet-wsm-fn.c"

static int
dissect_wsm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *wsm_item = NULL;
  proto_tree *wsm_tree = NULL;

  int offset;
  guint8 check;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEEE 1609.3 - WAVE Short Message");
  col_set_str(pinfo->cinfo, COL_INFO, "WAVE Short Message");

  wsm_item = proto_tree_add_item(tree, proto_wsm, tvb, 0, -1, FALSE);
  wsm_tree = proto_item_add_subtree(wsm_item, ett_wsm);

  offset = dissect_ShortMsgNpdu_PDU(tvb, pinfo, wsm_tree, data);

  if (data_tvb)
    return call_data_dissector(data_tvb, pinfo, tree);

  return offset;
}

void proto_register_wsm(void) {
  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-wsm-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_wsm,
#include "packet-wsm-ettarr.c"
  };

  /* Register protocol */
  proto_wsm = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_wsm, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  register_dissector("wsm", dissect_wsm, proto_wsm);
}

void proto_reg_handoff_wsm(void)
{
  dissector_handle_t wsm_handle = find_dissector("wsm");
  dissector_add_uint("ethertype", ETHERTYPE_WSMP, wsm_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */

/* packet-wsa.c
 * Routines for IEEE Std 1609.3 WSA packet dissection
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

#include <wsutil/str_util.h>

#include "packet-per.h"
#include "packet-wsa.h"

#define PNAME  "IEEE 1609.3 - WAVE Service Advertisement"
#define PSNAME "IEEE 1609.3 WSA"
#define PFNAME "wsa"

static int proto_wsa = -1;

static guint32 extensionId = -1;

static int
dissect_wsa_TwoDLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int
dissect_wsa_ThreeDLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int
dissect_wsa_AdvertiserIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int
dissect_wsa_ProviderServiceContext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int
dissect_wsa_IPv6Address(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int
dissect_wsa_ServicePort(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int
dissect_wsa_ProviderMacAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int
dissect_wsa_EdcaParameterSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int
dissect_wsa_SecondaryDns(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int
dissect_wsa_GatewayMacAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int
dissect_wsa_RepeatRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int
dissect_wsa_RcpiThreshold(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int
dissect_wsa_WsaCountThreshold(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int
dissect_wsa_ChannelAccess80211(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int
dissect_wsa_WsaCountThresholdInterval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

#include "packet-wsa-hf.c"

static int ett_wsa = -1;

#include "packet-wsa-ett.c"
#include "packet-wsa-fn.c"

static int
dissect_wsa(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *wsa_item = NULL;
  proto_tree *wsa_tree = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEEE 1609.3");
  col_set_str(pinfo->cinfo, COL_INFO, "WAVE Service Advertisement");

  wsa_item = proto_tree_add_item(tree, proto_wsa, tvb, 0, -1, FALSE);
  wsa_tree = proto_item_add_subtree(wsa_item, ett_wsa);

  return dissect_SrvAdvMsg_PDU(tvb, pinfo, wsa_tree, data);
}

void proto_register_wsa(void) {
  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-wsa-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_wsa,
#include "packet-wsa-ettarr.c"
  };

  /* Register protocol */
  proto_wsa = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_wsa, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  register_dissector("ieee1609dot3wsa", dissect_wsa, proto_wsa);
}

void proto_reg_handoff_wsa(void)
{
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

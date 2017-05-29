/* packet-j2735.c
 * Routines for SAE J273 Mar2016 packet dissection
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
#include "packet-j2735.h"

#define PNAME  "SAE J2735 DSRC Message Set Dictionary"
#define PSNAME "J2735"
#define PFNAME "j2735"

static int proto_j2735 = -1;

static guint32 mid = -1;
static guint32 pid = -1;

#include "packet-j2735-hf.c"

static int ett_j2735 = -1;

#include "packet-j2735-ett.c"
#include "packet-j2735-fn.c"

#define MIN_DSRC_MSG 0
#define NUM_DSRC_MSG 15

static const char *DSRC_MSG_NAME[NUM_DSRC_MSG] =
{
};

static const char *DSRC_MSG_ABBR[NUM_DSRC_MSG] =
{
};

static int
dissect_j2735(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *j2735_item = NULL;
  proto_tree *j2735_tree = NULL;

  int offset = -1;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SAE J2735");
  col_set_str(pinfo->cinfo, COL_INFO, "DSRC Message Set Dictionary");

  j2735_item = proto_tree_add_item(tree, proto_j2735, tvb, 0, -1, FALSE);
  j2735_tree = proto_item_add_subtree(j2735_item, ett_j2735);

  offset = dissect_MessageFrame_PDU(tvb, pinfo, j2735_tree, data);

  if (mid >= MIN_DSRC_MSG && mid < (MIN_DSRC_MSG + NUM_DSRC_MSG)) {
    col_append_fstr(pinfo->cinfo, COL_PROTOCOL, " - %s", DSRC_MSG_ABBR[mid - MIN_DSRC_MSG]);
    col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", DSRC_MSG_NAME[mid - MIN_DSRC_MSG]);
  }

  return offset;
}

void proto_register_j2735(void) {
  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-j2735-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_j2735,
#include "packet-j2735-ettarr.c"
  };

  /* Register protocol */
  proto_j2735 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_j2735, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  register_dissector("j2735", dissect_j2735, proto_j2735);
}

void proto_reg_handoff_j2735(void)
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

/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-wsm.c                                                               */
/* asn2wrs.py -L -S -p wsm -c ./wsm.cnf -s ./packet-wsm-template -D . -O ../.. CITSapplMgmtIDs.asn wee.asn wsm.asn */

/* Input file: packet-wsm-template.c */

#line 1 "./asn1/wsm/packet-wsm-template.c"
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


/*--- Included file: packet-wsm-hf.c ---*/
#line 1 "./asn1/wsm/packet-wsm-hf.c"
static int hf_wsm_ShortMsgNpdu_PDU = -1;          /* ShortMsgNpdu */
static int hf_wsm_content = -1;                   /* INTEGER_0_127 */
static int hf_wsm_extension = -1;                 /* Ext1 */
static int hf_wsm_content_01 = -1;                /* INTEGER_128_16511 */
static int hf_wsm_extension_01 = -1;              /* Ext2 */
static int hf_wsm_content_02 = -1;                /* INTEGER_16512_2113663 */
static int hf_wsm_extension_02 = -1;              /* Ext3 */
static int hf_wsm_extensionId = -1;               /* RefExt */
static int hf_wsm_value = -1;                     /* T_value */
static int hf_wsm_dataRate80211 = -1;             /* INTEGER_0_255 */
static int hf_wsm_txpower80211 = -1;              /* INTEGER_M128_127 */
static int hf_wsm_channelNumber80211 = -1;        /* INTEGER_0_255 */
static int hf_wsm_subtype = -1;                   /* ShortMsgSubtype */
static int hf_wsm_transport = -1;                 /* ShortMsgTpdus */
static int hf_wsm_body = -1;                      /* ShortMsgData */
static int hf_wsm_nullNetworking = -1;            /* NullNetworking */
static int hf_wsm_subTypeReserved1 = -1;          /* NoSubtypeProcessing */
static int hf_wsm_subTypeReserved2 = -1;          /* NoSubtypeProcessing */
static int hf_wsm_subTypeReserved3 = -1;          /* NoSubtypeProcessing */
static int hf_wsm_subTypeReserved4 = -1;          /* NoSubtypeProcessing */
static int hf_wsm_subTypeReserved5 = -1;          /* NoSubtypeProcessing */
static int hf_wsm_subTypeReserved6 = -1;          /* NoSubtypeProcessing */
static int hf_wsm_subTypeReserved7 = -1;          /* NoSubtypeProcessing */
static int hf_wsm_subTypeReserved8 = -1;          /* NoSubtypeProcessing */
static int hf_wsm_subTypeReserved9 = -1;          /* NoSubtypeProcessing */
static int hf_wsm_subTypeReserved19 = -1;         /* NoSubtypeProcessing */
static int hf_wsm_subTypeReserved11 = -1;         /* NoSubtypeProcessing */
static int hf_wsm_subTypeReserved12 = -1;         /* NoSubtypeProcessing */
static int hf_wsm_subTypeReserved13 = -1;         /* NoSubtypeProcessing */
static int hf_wsm_subTypeReserved14 = -1;         /* NoSubtypeProcessing */
static int hf_wsm_subTypeReserved15 = -1;         /* NoSubtypeProcessing */
static int hf_wsm_optBit = -1;                    /* BIT_STRING_SIZE_1 */
static int hf_wsm_version = -1;                   /* ShortMsgVersion */
static int hf_wsm_nExtensions = -1;               /* ShortMsgNextensions */
static int hf_wsm_ShortMsgNextensions_item = -1;  /* ShortMsgNextension */
static int hf_wsm_bcMode = -1;                    /* ShortMsgBcPDU */
static int hf_wsm_tpidReserved1 = -1;             /* NoTpidProcessing */
static int hf_wsm_tpidReserved2 = -1;             /* NoTpidProcessing */
static int hf_wsm_tpidReserved3 = -1;             /* NoTpidProcessing */
static int hf_wsm_tpidReserved4 = -1;             /* NoTpidProcessing */
static int hf_wsm_tpidReserved5 = -1;             /* NoTpidProcessing */
static int hf_wsm_tpidReserved6 = -1;             /* NoTpidProcessing */
static int hf_wsm_tpidReserved7 = -1;             /* NoTpidProcessing */
static int hf_wsm_tpidReserved8 = -1;             /* NoTpidProcessing */
static int hf_wsm_tpidReserved9 = -1;             /* NoTpidProcessing */
static int hf_wsm_tpidReserved10 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved11 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved12 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved13 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved14 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved15 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved16 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved17 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved18 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved19 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved20 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved21 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved22 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved23 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved24 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved25 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved26 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved27 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved28 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved29 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved30 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved31 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved32 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved33 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved34 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved35 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved36 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved37 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved38 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved39 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved40 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved41 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved42 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved43 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved44 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved45 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved46 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved47 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved48 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved49 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved50 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved51 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved52 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved53 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved54 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved55 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved56 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved57 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved58 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved59 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved60 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved61 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved62 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved63 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved64 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved65 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved66 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved67 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved68 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved69 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved70 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved71 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved72 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved73 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved74 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved75 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved76 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved77 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved78 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved79 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved80 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved81 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved82 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved83 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved84 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved85 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved86 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved87 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved88 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved89 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved90 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved91 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved92 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved93 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved94 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved95 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved96 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved97 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved98 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved99 = -1;            /* NoTpidProcessing */
static int hf_wsm_tpidReserved100 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved101 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved102 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved103 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved104 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved105 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved106 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved107 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved108 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved109 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved110 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved111 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved112 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved113 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved114 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved115 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved116 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved117 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved118 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved119 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved120 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved121 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved122 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved123 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved124 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved125 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved126 = -1;           /* NoTpidProcessing */
static int hf_wsm_tpidReserved127 = -1;           /* NoTpidProcessing */
static int hf_wsm_destAddress = -1;               /* VarLengthNumber */
static int hf_wsm_tExtensions = -1;               /* ShortMsgTextensions */
static int hf_wsm_ShortMsgTextensions_item = -1;  /* ShortMsgTextension */

/*--- End of included file: packet-wsm-hf.c ---*/
#line 60 "./asn1/wsm/packet-wsm-template.c"

static int ett_wsm = -1;


/*--- Included file: packet-wsm-ett.c ---*/
#line 1 "./asn1/wsm/packet-wsm-ett.c"
static gint ett_wsm_VarLengthNumber = -1;
static gint ett_wsm_Ext1 = -1;
static gint ett_wsm_Ext2 = -1;
static gint ett_wsm_Extension = -1;
static gint ett_wsm_DataRate80211 = -1;
static gint ett_wsm_TXpower80211 = -1;
static gint ett_wsm_ChannelNumber80211 = -1;
static gint ett_wsm_ShortMsgNpdu = -1;
static gint ett_wsm_ShortMsgSubtype = -1;
static gint ett_wsm_NoSubtypeProcessing = -1;
static gint ett_wsm_NullNetworking = -1;
static gint ett_wsm_ShortMsgNextensions = -1;
static gint ett_wsm_ShortMsgTpdus = -1;
static gint ett_wsm_ShortMsgBcPDU = -1;
static gint ett_wsm_ShortMsgTextensions = -1;

/*--- End of included file: packet-wsm-ett.c ---*/
#line 64 "./asn1/wsm/packet-wsm-template.c"

/*--- Included file: packet-wsm-fn.c ---*/
#line 1 "./asn1/wsm/packet-wsm-fn.c"


static int
dissect_wsm_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_wsm_INTEGER_128_16511(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            128U, 16511U, NULL, FALSE);

  return offset;
}



static int
dissect_wsm_INTEGER_16512_2113663(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            16512U, 2113663U, NULL, FALSE);

  return offset;
}



static int
dissect_wsm_Ext3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            2113664U, 270549119U, NULL, TRUE);

  return offset;
}


static const value_string wsm_Ext2_vals[] = {
  {   0, "content" },
  {   1, "extension" },
  { 0, NULL }
};

static const per_choice_t Ext2_choice[] = {
  {   0, &hf_wsm_content_02      , ASN1_NO_EXTENSIONS     , dissect_wsm_INTEGER_16512_2113663 },
  {   1, &hf_wsm_extension_02    , ASN1_NO_EXTENSIONS     , dissect_wsm_Ext3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_wsm_Ext2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_wsm_Ext2, Ext2_choice,
                                 NULL);

  return offset;
}


static const value_string wsm_Ext1_vals[] = {
  {   0, "content" },
  {   1, "extension" },
  { 0, NULL }
};

static const per_choice_t Ext1_choice[] = {
  {   0, &hf_wsm_content_01      , ASN1_NO_EXTENSIONS     , dissect_wsm_INTEGER_128_16511 },
  {   1, &hf_wsm_extension_01    , ASN1_NO_EXTENSIONS     , dissect_wsm_Ext2 },
  { 0, NULL, 0, NULL }
};

static int
dissect_wsm_Ext1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_wsm_Ext1, Ext1_choice,
                                 NULL);

  return offset;
}


static const value_string wsm_VarLengthNumber_vals[] = {
  {   0, "content" },
  {   1, "extension" },
  { 0, NULL }
};

static const per_choice_t VarLengthNumber_choice[] = {
  {   0, &hf_wsm_content         , ASN1_NO_EXTENSIONS     , dissect_wsm_INTEGER_0_127 },
  {   1, &hf_wsm_extension       , ASN1_NO_EXTENSIONS     , dissect_wsm_Ext1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_wsm_VarLengthNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_wsm_VarLengthNumber, VarLengthNumber_choice,
                                 NULL);

  return offset;
}


static const value_string wsm_RefExt_vals[] = {
  {   0, "c-Reserved" },
  {   4, "c-TxPowerUsed80211" },
  {   5, "c-2Dlocation" },
  {   6, "c-3Dlocation" },
  {   7, "c-advertiserID" },
  {   8, "c-ProviderServContext" },
  {   9, "c-IPv6Address" },
  {  10, "c-servicePort" },
  {  11, "c-ProviderMACaddress" },
  {  12, "c-EDCAparameterSet" },
  {  13, "c-SecondaryDNS" },
  {  14, "c-GatewayMACaddress" },
  {  15, "c-ChannelNumber80211" },
  {  16, "c-DataRate80211" },
  {  17, "c-RepeatRate" },
  {  19, "c-RCPIthreshold" },
  {  20, "c-WSAcountThreshold" },
  {  21, "c-ChannelAccess" },
  {  22, "c-WSAcountThresInt" },
  {  23, "c-ChannelLoad" },
  { 0, NULL }
};


static int
dissect_wsm_RefExt(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &extensionId, FALSE);

  return offset;
}



static int
dissect_wsm_T_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  switch (extensionId) {
  case 4:
    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_wsm_TXpower80211);
    break;
  case 15:
    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_wsm_ChannelNumber80211);
    break;
  case 16:
    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_wsm_DataRate80211);
    break;
  default:
    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);
    break;
  }

  return offset;
}


static const per_sequence_t Extension_sequence[] = {
  { &hf_wsm_extensionId     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsm_RefExt },
  { &hf_wsm_value           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsm_T_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsm_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsm_Extension, Extension_sequence);

  return offset;
}



static int
dissect_wsm_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t DataRate80211_sequence[] = {
  { &hf_wsm_dataRate80211   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsm_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsm_DataRate80211(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsm_DataRate80211, DataRate80211_sequence);

  return offset;
}



static int
dissect_wsm_INTEGER_M128_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -128, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t TXpower80211_sequence[] = {
  { &hf_wsm_txpower80211    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsm_INTEGER_M128_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsm_TXpower80211(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsm_TXpower80211, TXpower80211_sequence);

  return offset;
}


static const per_sequence_t ChannelNumber80211_sequence[] = {
  { &hf_wsm_channelNumber80211, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsm_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsm_ChannelNumber80211(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsm_ChannelNumber80211, ChannelNumber80211_sequence);

  return offset;
}


static const value_string wsm_ShortMsgVersion_vals[] = {
  {   3, "c-shortMsgVersionNo" },
  { 0, NULL }
};


static int
dissect_wsm_ShortMsgVersion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}



static int
dissect_wsm_ShortMsgNextension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_wsm_Extension(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t ShortMsgNextensions_sequence_of[1] = {
  { &hf_wsm_ShortMsgNextensions_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsm_ShortMsgNextension },
};

static int
dissect_wsm_ShortMsgNextensions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_wsm_ShortMsgNextensions, ShortMsgNextensions_sequence_of);

  return offset;
}


static const per_sequence_t NullNetworking_sequence[] = {
  { &hf_wsm_version         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsm_ShortMsgVersion },
  { &hf_wsm_nExtensions     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_wsm_ShortMsgNextensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsm_NullNetworking(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsm_NullNetworking, NullNetworking_sequence);

  return offset;
}



static int
dissect_wsm_BIT_STRING_SIZE_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 1, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t NoSubtypeProcessing_sequence[] = {
  { &hf_wsm_optBit          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsm_BIT_STRING_SIZE_1 },
  { &hf_wsm_version         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsm_ShortMsgVersion },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsm_NoSubtypeProcessing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsm_NoSubtypeProcessing, NoSubtypeProcessing_sequence);

  return offset;
}


static const value_string wsm_ShortMsgSubtype_vals[] = {
  {   0, "nullNetworking" },
  {   1, "subTypeReserved1" },
  {   2, "subTypeReserved2" },
  {   3, "subTypeReserved3" },
  {   4, "subTypeReserved4" },
  {   5, "subTypeReserved5" },
  {   6, "subTypeReserved6" },
  {   7, "subTypeReserved7" },
  {   8, "subTypeReserved8" },
  {   9, "subTypeReserved9" },
  {  10, "subTypeReserved19" },
  {  11, "subTypeReserved11" },
  {  12, "subTypeReserved12" },
  {  13, "subTypeReserved13" },
  {  14, "subTypeReserved14" },
  {  15, "subTypeReserved15" },
  { 0, NULL }
};

static const per_choice_t ShortMsgSubtype_choice[] = {
  {   0, &hf_wsm_nullNetworking  , ASN1_NO_EXTENSIONS     , dissect_wsm_NullNetworking },
  {   1, &hf_wsm_subTypeReserved1, ASN1_NO_EXTENSIONS     , dissect_wsm_NoSubtypeProcessing },
  {   2, &hf_wsm_subTypeReserved2, ASN1_NO_EXTENSIONS     , dissect_wsm_NoSubtypeProcessing },
  {   3, &hf_wsm_subTypeReserved3, ASN1_NO_EXTENSIONS     , dissect_wsm_NoSubtypeProcessing },
  {   4, &hf_wsm_subTypeReserved4, ASN1_NO_EXTENSIONS     , dissect_wsm_NoSubtypeProcessing },
  {   5, &hf_wsm_subTypeReserved5, ASN1_NO_EXTENSIONS     , dissect_wsm_NoSubtypeProcessing },
  {   6, &hf_wsm_subTypeReserved6, ASN1_NO_EXTENSIONS     , dissect_wsm_NoSubtypeProcessing },
  {   7, &hf_wsm_subTypeReserved7, ASN1_NO_EXTENSIONS     , dissect_wsm_NoSubtypeProcessing },
  {   8, &hf_wsm_subTypeReserved8, ASN1_NO_EXTENSIONS     , dissect_wsm_NoSubtypeProcessing },
  {   9, &hf_wsm_subTypeReserved9, ASN1_NO_EXTENSIONS     , dissect_wsm_NoSubtypeProcessing },
  {  10, &hf_wsm_subTypeReserved19, ASN1_NO_EXTENSIONS     , dissect_wsm_NoSubtypeProcessing },
  {  11, &hf_wsm_subTypeReserved11, ASN1_NO_EXTENSIONS     , dissect_wsm_NoSubtypeProcessing },
  {  12, &hf_wsm_subTypeReserved12, ASN1_NO_EXTENSIONS     , dissect_wsm_NoSubtypeProcessing },
  {  13, &hf_wsm_subTypeReserved13, ASN1_NO_EXTENSIONS     , dissect_wsm_NoSubtypeProcessing },
  {  14, &hf_wsm_subTypeReserved14, ASN1_NO_EXTENSIONS     , dissect_wsm_NoSubtypeProcessing },
  {  15, &hf_wsm_subTypeReserved15, ASN1_NO_EXTENSIONS     , dissect_wsm_NoSubtypeProcessing },
  { 0, NULL, 0, NULL }
};

static int
dissect_wsm_ShortMsgSubtype(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_wsm_ShortMsgSubtype, ShortMsgSubtype_choice,
                                 NULL);

  return offset;
}



static int
dissect_wsm_ShortMsgTextension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_wsm_Extension(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t ShortMsgTextensions_sequence_of[1] = {
  { &hf_wsm_ShortMsgTextensions_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsm_ShortMsgTextension },
};

static int
dissect_wsm_ShortMsgTextensions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_wsm_ShortMsgTextensions, ShortMsgTextensions_sequence_of);

  return offset;
}


static const per_sequence_t ShortMsgBcPDU_sequence[] = {
  { &hf_wsm_destAddress     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsm_VarLengthNumber },
  { &hf_wsm_tExtensions     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_wsm_ShortMsgTextensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsm_ShortMsgBcPDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsm_ShortMsgBcPDU, ShortMsgBcPDU_sequence);

  return offset;
}



static int
dissect_wsm_NoTpidProcessing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 1, FALSE, NULL, NULL);

  return offset;
}


static const value_string wsm_ShortMsgTpdus_vals[] = {
  {   0, "bcMode" },
  {   1, "tpidReserved1" },
  {   2, "tpidReserved2" },
  {   3, "tpidReserved3" },
  {   4, "tpidReserved4" },
  {   5, "tpidReserved5" },
  {   6, "tpidReserved6" },
  {   7, "tpidReserved7" },
  {   8, "tpidReserved8" },
  {   9, "tpidReserved9" },
  {  10, "tpidReserved10" },
  {  11, "tpidReserved11" },
  {  12, "tpidReserved12" },
  {  13, "tpidReserved13" },
  {  14, "tpidReserved14" },
  {  15, "tpidReserved15" },
  {  16, "tpidReserved16" },
  {  17, "tpidReserved17" },
  {  18, "tpidReserved18" },
  {  19, "tpidReserved19" },
  {  20, "tpidReserved20" },
  {  21, "tpidReserved21" },
  {  22, "tpidReserved22" },
  {  23, "tpidReserved23" },
  {  24, "tpidReserved24" },
  {  25, "tpidReserved25" },
  {  26, "tpidReserved26" },
  {  27, "tpidReserved27" },
  {  28, "tpidReserved28" },
  {  29, "tpidReserved29" },
  {  30, "tpidReserved30" },
  {  31, "tpidReserved31" },
  {  32, "tpidReserved32" },
  {  33, "tpidReserved33" },
  {  34, "tpidReserved34" },
  {  35, "tpidReserved35" },
  {  36, "tpidReserved36" },
  {  37, "tpidReserved37" },
  {  38, "tpidReserved38" },
  {  39, "tpidReserved39" },
  {  40, "tpidReserved40" },
  {  41, "tpidReserved41" },
  {  42, "tpidReserved42" },
  {  43, "tpidReserved43" },
  {  44, "tpidReserved44" },
  {  45, "tpidReserved45" },
  {  46, "tpidReserved46" },
  {  47, "tpidReserved47" },
  {  48, "tpidReserved48" },
  {  49, "tpidReserved49" },
  {  50, "tpidReserved50" },
  {  51, "tpidReserved51" },
  {  52, "tpidReserved52" },
  {  53, "tpidReserved53" },
  {  54, "tpidReserved54" },
  {  55, "tpidReserved55" },
  {  56, "tpidReserved56" },
  {  57, "tpidReserved57" },
  {  58, "tpidReserved58" },
  {  59, "tpidReserved59" },
  {  60, "tpidReserved60" },
  {  61, "tpidReserved61" },
  {  62, "tpidReserved62" },
  {  63, "tpidReserved63" },
  {  64, "tpidReserved64" },
  {  65, "tpidReserved65" },
  {  66, "tpidReserved66" },
  {  67, "tpidReserved67" },
  {  68, "tpidReserved68" },
  {  69, "tpidReserved69" },
  {  70, "tpidReserved70" },
  {  71, "tpidReserved71" },
  {  72, "tpidReserved72" },
  {  73, "tpidReserved73" },
  {  74, "tpidReserved74" },
  {  75, "tpidReserved75" },
  {  76, "tpidReserved76" },
  {  77, "tpidReserved77" },
  {  78, "tpidReserved78" },
  {  79, "tpidReserved79" },
  {  80, "tpidReserved80" },
  {  81, "tpidReserved81" },
  {  82, "tpidReserved82" },
  {  83, "tpidReserved83" },
  {  84, "tpidReserved84" },
  {  85, "tpidReserved85" },
  {  86, "tpidReserved86" },
  {  87, "tpidReserved87" },
  {  88, "tpidReserved88" },
  {  89, "tpidReserved89" },
  {  90, "tpidReserved90" },
  {  91, "tpidReserved91" },
  {  92, "tpidReserved92" },
  {  93, "tpidReserved93" },
  {  94, "tpidReserved94" },
  {  95, "tpidReserved95" },
  {  96, "tpidReserved96" },
  {  97, "tpidReserved97" },
  {  98, "tpidReserved98" },
  {  99, "tpidReserved99" },
  { 100, "tpidReserved100" },
  { 101, "tpidReserved101" },
  { 102, "tpidReserved102" },
  { 103, "tpidReserved103" },
  { 104, "tpidReserved104" },
  { 105, "tpidReserved105" },
  { 106, "tpidReserved106" },
  { 107, "tpidReserved107" },
  { 108, "tpidReserved108" },
  { 109, "tpidReserved109" },
  { 110, "tpidReserved110" },
  { 111, "tpidReserved111" },
  { 112, "tpidReserved112" },
  { 113, "tpidReserved113" },
  { 114, "tpidReserved114" },
  { 115, "tpidReserved115" },
  { 116, "tpidReserved116" },
  { 117, "tpidReserved117" },
  { 118, "tpidReserved118" },
  { 119, "tpidReserved119" },
  { 120, "tpidReserved120" },
  { 121, "tpidReserved121" },
  { 122, "tpidReserved122" },
  { 123, "tpidReserved123" },
  { 124, "tpidReserved124" },
  { 125, "tpidReserved125" },
  { 126, "tpidReserved126" },
  { 127, "tpidReserved127" },
  { 0, NULL }
};

static const per_choice_t ShortMsgTpdus_choice[] = {
  {   0, &hf_wsm_bcMode          , ASN1_NO_EXTENSIONS     , dissect_wsm_ShortMsgBcPDU },
  {   1, &hf_wsm_tpidReserved1   , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {   2, &hf_wsm_tpidReserved2   , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {   3, &hf_wsm_tpidReserved3   , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {   4, &hf_wsm_tpidReserved4   , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {   5, &hf_wsm_tpidReserved5   , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {   6, &hf_wsm_tpidReserved6   , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {   7, &hf_wsm_tpidReserved7   , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {   8, &hf_wsm_tpidReserved8   , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {   9, &hf_wsm_tpidReserved9   , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  10, &hf_wsm_tpidReserved10  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  11, &hf_wsm_tpidReserved11  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  12, &hf_wsm_tpidReserved12  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  13, &hf_wsm_tpidReserved13  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  14, &hf_wsm_tpidReserved14  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  15, &hf_wsm_tpidReserved15  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  16, &hf_wsm_tpidReserved16  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  17, &hf_wsm_tpidReserved17  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  18, &hf_wsm_tpidReserved18  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  19, &hf_wsm_tpidReserved19  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  20, &hf_wsm_tpidReserved20  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  21, &hf_wsm_tpidReserved21  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  22, &hf_wsm_tpidReserved22  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  23, &hf_wsm_tpidReserved23  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  24, &hf_wsm_tpidReserved24  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  25, &hf_wsm_tpidReserved25  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  26, &hf_wsm_tpidReserved26  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  27, &hf_wsm_tpidReserved27  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  28, &hf_wsm_tpidReserved28  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  29, &hf_wsm_tpidReserved29  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  30, &hf_wsm_tpidReserved30  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  31, &hf_wsm_tpidReserved31  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  32, &hf_wsm_tpidReserved32  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  33, &hf_wsm_tpidReserved33  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  34, &hf_wsm_tpidReserved34  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  35, &hf_wsm_tpidReserved35  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  36, &hf_wsm_tpidReserved36  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  37, &hf_wsm_tpidReserved37  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  38, &hf_wsm_tpidReserved38  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  39, &hf_wsm_tpidReserved39  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  40, &hf_wsm_tpidReserved40  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  41, &hf_wsm_tpidReserved41  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  42, &hf_wsm_tpidReserved42  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  43, &hf_wsm_tpidReserved43  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  44, &hf_wsm_tpidReserved44  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  45, &hf_wsm_tpidReserved45  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  46, &hf_wsm_tpidReserved46  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  47, &hf_wsm_tpidReserved47  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  48, &hf_wsm_tpidReserved48  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  49, &hf_wsm_tpidReserved49  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  50, &hf_wsm_tpidReserved50  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  51, &hf_wsm_tpidReserved51  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  52, &hf_wsm_tpidReserved52  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  53, &hf_wsm_tpidReserved53  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  54, &hf_wsm_tpidReserved54  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  55, &hf_wsm_tpidReserved55  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  56, &hf_wsm_tpidReserved56  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  57, &hf_wsm_tpidReserved57  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  58, &hf_wsm_tpidReserved58  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  59, &hf_wsm_tpidReserved59  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  60, &hf_wsm_tpidReserved60  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  61, &hf_wsm_tpidReserved61  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  62, &hf_wsm_tpidReserved62  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  63, &hf_wsm_tpidReserved63  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  64, &hf_wsm_tpidReserved64  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  65, &hf_wsm_tpidReserved65  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  66, &hf_wsm_tpidReserved66  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  67, &hf_wsm_tpidReserved67  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  68, &hf_wsm_tpidReserved68  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  69, &hf_wsm_tpidReserved69  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  70, &hf_wsm_tpidReserved70  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  71, &hf_wsm_tpidReserved71  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  72, &hf_wsm_tpidReserved72  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  73, &hf_wsm_tpidReserved73  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  74, &hf_wsm_tpidReserved74  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  75, &hf_wsm_tpidReserved75  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  76, &hf_wsm_tpidReserved76  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  77, &hf_wsm_tpidReserved77  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  78, &hf_wsm_tpidReserved78  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  79, &hf_wsm_tpidReserved79  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  80, &hf_wsm_tpidReserved80  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  81, &hf_wsm_tpidReserved81  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  82, &hf_wsm_tpidReserved82  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  83, &hf_wsm_tpidReserved83  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  84, &hf_wsm_tpidReserved84  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  85, &hf_wsm_tpidReserved85  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  86, &hf_wsm_tpidReserved86  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  87, &hf_wsm_tpidReserved87  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  88, &hf_wsm_tpidReserved88  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  89, &hf_wsm_tpidReserved89  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  90, &hf_wsm_tpidReserved90  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  91, &hf_wsm_tpidReserved91  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  92, &hf_wsm_tpidReserved92  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  93, &hf_wsm_tpidReserved93  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  94, &hf_wsm_tpidReserved94  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  95, &hf_wsm_tpidReserved95  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  96, &hf_wsm_tpidReserved96  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  97, &hf_wsm_tpidReserved97  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  98, &hf_wsm_tpidReserved98  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  {  99, &hf_wsm_tpidReserved99  , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 100, &hf_wsm_tpidReserved100 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 101, &hf_wsm_tpidReserved101 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 102, &hf_wsm_tpidReserved102 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 103, &hf_wsm_tpidReserved103 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 104, &hf_wsm_tpidReserved104 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 105, &hf_wsm_tpidReserved105 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 106, &hf_wsm_tpidReserved106 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 107, &hf_wsm_tpidReserved107 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 108, &hf_wsm_tpidReserved108 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 109, &hf_wsm_tpidReserved109 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 110, &hf_wsm_tpidReserved110 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 111, &hf_wsm_tpidReserved111 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 112, &hf_wsm_tpidReserved112 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 113, &hf_wsm_tpidReserved113 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 114, &hf_wsm_tpidReserved114 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 115, &hf_wsm_tpidReserved115 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 116, &hf_wsm_tpidReserved116 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 117, &hf_wsm_tpidReserved117 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 118, &hf_wsm_tpidReserved118 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 119, &hf_wsm_tpidReserved119 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 120, &hf_wsm_tpidReserved120 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 121, &hf_wsm_tpidReserved121 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 122, &hf_wsm_tpidReserved122 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 123, &hf_wsm_tpidReserved123 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 124, &hf_wsm_tpidReserved124 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 125, &hf_wsm_tpidReserved125 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 126, &hf_wsm_tpidReserved126 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 127, &hf_wsm_tpidReserved127 , ASN1_NO_EXTENSIONS     , dissect_wsm_NoTpidProcessing },
  { 0, NULL, 0, NULL }
};

static int
dissect_wsm_ShortMsgTpdus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_wsm_ShortMsgTpdus, ShortMsgTpdus_choice,
                                 NULL);

  return offset;
}



static int
dissect_wsm_ShortMsgData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &data_tvb);


  return offset;
}


static const per_sequence_t ShortMsgNpdu_sequence[] = {
  { &hf_wsm_subtype         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsm_ShortMsgSubtype },
  { &hf_wsm_transport       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsm_ShortMsgTpdus },
  { &hf_wsm_body            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsm_ShortMsgData },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsm_ShortMsgNpdu(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsm_ShortMsgNpdu, ShortMsgNpdu_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_ShortMsgNpdu_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_wsm_ShortMsgNpdu(tvb, offset, &asn1_ctx, tree, hf_wsm_ShortMsgNpdu_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-wsm-fn.c ---*/
#line 65 "./asn1/wsm/packet-wsm-template.c"

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

/*--- Included file: packet-wsm-hfarr.c ---*/
#line 1 "./asn1/wsm/packet-wsm-hfarr.c"
    { &hf_wsm_ShortMsgNpdu_PDU,
      { "ShortMsgNpdu", "wsm.ShortMsgNpdu_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsm_content,
      { "content", "wsm.content",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_wsm_extension,
      { "extension", "wsm.extension",
        FT_UINT32, BASE_DEC, VALS(wsm_Ext1_vals), 0,
        "Ext1", HFILL }},
    { &hf_wsm_content_01,
      { "content", "wsm.content",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_128_16511", HFILL }},
    { &hf_wsm_extension_01,
      { "extension", "wsm.extension",
        FT_UINT32, BASE_DEC, VALS(wsm_Ext2_vals), 0,
        "Ext2", HFILL }},
    { &hf_wsm_content_02,
      { "content", "wsm.content",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_16512_2113663", HFILL }},
    { &hf_wsm_extension_02,
      { "extension", "wsm.extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Ext3", HFILL }},
    { &hf_wsm_extensionId,
      { "extensionId", "wsm.extensionId",
        FT_UINT32, BASE_DEC, VALS(wsm_RefExt_vals), 0,
        "RefExt", HFILL }},
    { &hf_wsm_value,
      { "value", "wsm.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsm_dataRate80211,
      { "dataRate80211", "wsm.dataRate80211",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_wsm_txpower80211,
      { "txpower80211", "wsm.txpower80211",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_wsm_channelNumber80211,
      { "channelNumber80211", "wsm.channelNumber80211",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_wsm_subtype,
      { "subtype", "wsm.subtype",
        FT_UINT32, BASE_DEC, VALS(wsm_ShortMsgSubtype_vals), 0,
        "ShortMsgSubtype", HFILL }},
    { &hf_wsm_transport,
      { "transport", "wsm.transport",
        FT_UINT32, BASE_DEC, VALS(wsm_ShortMsgTpdus_vals), 0,
        "ShortMsgTpdus", HFILL }},
    { &hf_wsm_body,
      { "body", "wsm.body",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ShortMsgData", HFILL }},
    { &hf_wsm_nullNetworking,
      { "nullNetworking", "wsm.nullNetworking_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsm_subTypeReserved1,
      { "subTypeReserved1", "wsm.subTypeReserved1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NoSubtypeProcessing", HFILL }},
    { &hf_wsm_subTypeReserved2,
      { "subTypeReserved2", "wsm.subTypeReserved2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NoSubtypeProcessing", HFILL }},
    { &hf_wsm_subTypeReserved3,
      { "subTypeReserved3", "wsm.subTypeReserved3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NoSubtypeProcessing", HFILL }},
    { &hf_wsm_subTypeReserved4,
      { "subTypeReserved4", "wsm.subTypeReserved4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NoSubtypeProcessing", HFILL }},
    { &hf_wsm_subTypeReserved5,
      { "subTypeReserved5", "wsm.subTypeReserved5_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NoSubtypeProcessing", HFILL }},
    { &hf_wsm_subTypeReserved6,
      { "subTypeReserved6", "wsm.subTypeReserved6_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NoSubtypeProcessing", HFILL }},
    { &hf_wsm_subTypeReserved7,
      { "subTypeReserved7", "wsm.subTypeReserved7_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NoSubtypeProcessing", HFILL }},
    { &hf_wsm_subTypeReserved8,
      { "subTypeReserved8", "wsm.subTypeReserved8_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NoSubtypeProcessing", HFILL }},
    { &hf_wsm_subTypeReserved9,
      { "subTypeReserved9", "wsm.subTypeReserved9_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NoSubtypeProcessing", HFILL }},
    { &hf_wsm_subTypeReserved19,
      { "subTypeReserved19", "wsm.subTypeReserved19_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NoSubtypeProcessing", HFILL }},
    { &hf_wsm_subTypeReserved11,
      { "subTypeReserved11", "wsm.subTypeReserved11_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NoSubtypeProcessing", HFILL }},
    { &hf_wsm_subTypeReserved12,
      { "subTypeReserved12", "wsm.subTypeReserved12_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NoSubtypeProcessing", HFILL }},
    { &hf_wsm_subTypeReserved13,
      { "subTypeReserved13", "wsm.subTypeReserved13_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NoSubtypeProcessing", HFILL }},
    { &hf_wsm_subTypeReserved14,
      { "subTypeReserved14", "wsm.subTypeReserved14_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NoSubtypeProcessing", HFILL }},
    { &hf_wsm_subTypeReserved15,
      { "subTypeReserved15", "wsm.subTypeReserved15_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NoSubtypeProcessing", HFILL }},
    { &hf_wsm_optBit,
      { "optBit", "wsm.optBit",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1", HFILL }},
    { &hf_wsm_version,
      { "version", "wsm.version",
        FT_UINT32, BASE_DEC, VALS(wsm_ShortMsgVersion_vals), 0,
        "ShortMsgVersion", HFILL }},
    { &hf_wsm_nExtensions,
      { "nExtensions", "wsm.nExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ShortMsgNextensions", HFILL }},
    { &hf_wsm_ShortMsgNextensions_item,
      { "ShortMsgNextension", "wsm.ShortMsgNextension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsm_bcMode,
      { "bcMode", "wsm.bcMode_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ShortMsgBcPDU", HFILL }},
    { &hf_wsm_tpidReserved1,
      { "tpidReserved1", "wsm.tpidReserved1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved2,
      { "tpidReserved2", "wsm.tpidReserved2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved3,
      { "tpidReserved3", "wsm.tpidReserved3",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved4,
      { "tpidReserved4", "wsm.tpidReserved4",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved5,
      { "tpidReserved5", "wsm.tpidReserved5",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved6,
      { "tpidReserved6", "wsm.tpidReserved6",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved7,
      { "tpidReserved7", "wsm.tpidReserved7",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved8,
      { "tpidReserved8", "wsm.tpidReserved8",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved9,
      { "tpidReserved9", "wsm.tpidReserved9",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved10,
      { "tpidReserved10", "wsm.tpidReserved10",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved11,
      { "tpidReserved11", "wsm.tpidReserved11",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved12,
      { "tpidReserved12", "wsm.tpidReserved12",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved13,
      { "tpidReserved13", "wsm.tpidReserved13",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved14,
      { "tpidReserved14", "wsm.tpidReserved14",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved15,
      { "tpidReserved15", "wsm.tpidReserved15",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved16,
      { "tpidReserved16", "wsm.tpidReserved16",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved17,
      { "tpidReserved17", "wsm.tpidReserved17",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved18,
      { "tpidReserved18", "wsm.tpidReserved18",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved19,
      { "tpidReserved19", "wsm.tpidReserved19",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved20,
      { "tpidReserved20", "wsm.tpidReserved20",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved21,
      { "tpidReserved21", "wsm.tpidReserved21",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved22,
      { "tpidReserved22", "wsm.tpidReserved22",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved23,
      { "tpidReserved23", "wsm.tpidReserved23",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved24,
      { "tpidReserved24", "wsm.tpidReserved24",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved25,
      { "tpidReserved25", "wsm.tpidReserved25",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved26,
      { "tpidReserved26", "wsm.tpidReserved26",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved27,
      { "tpidReserved27", "wsm.tpidReserved27",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved28,
      { "tpidReserved28", "wsm.tpidReserved28",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved29,
      { "tpidReserved29", "wsm.tpidReserved29",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved30,
      { "tpidReserved30", "wsm.tpidReserved30",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved31,
      { "tpidReserved31", "wsm.tpidReserved31",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved32,
      { "tpidReserved32", "wsm.tpidReserved32",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved33,
      { "tpidReserved33", "wsm.tpidReserved33",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved34,
      { "tpidReserved34", "wsm.tpidReserved34",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved35,
      { "tpidReserved35", "wsm.tpidReserved35",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved36,
      { "tpidReserved36", "wsm.tpidReserved36",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved37,
      { "tpidReserved37", "wsm.tpidReserved37",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved38,
      { "tpidReserved38", "wsm.tpidReserved38",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved39,
      { "tpidReserved39", "wsm.tpidReserved39",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved40,
      { "tpidReserved40", "wsm.tpidReserved40",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved41,
      { "tpidReserved41", "wsm.tpidReserved41",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved42,
      { "tpidReserved42", "wsm.tpidReserved42",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved43,
      { "tpidReserved43", "wsm.tpidReserved43",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved44,
      { "tpidReserved44", "wsm.tpidReserved44",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved45,
      { "tpidReserved45", "wsm.tpidReserved45",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved46,
      { "tpidReserved46", "wsm.tpidReserved46",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved47,
      { "tpidReserved47", "wsm.tpidReserved47",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved48,
      { "tpidReserved48", "wsm.tpidReserved48",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved49,
      { "tpidReserved49", "wsm.tpidReserved49",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved50,
      { "tpidReserved50", "wsm.tpidReserved50",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved51,
      { "tpidReserved51", "wsm.tpidReserved51",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved52,
      { "tpidReserved52", "wsm.tpidReserved52",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved53,
      { "tpidReserved53", "wsm.tpidReserved53",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved54,
      { "tpidReserved54", "wsm.tpidReserved54",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved55,
      { "tpidReserved55", "wsm.tpidReserved55",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved56,
      { "tpidReserved56", "wsm.tpidReserved56",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved57,
      { "tpidReserved57", "wsm.tpidReserved57",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved58,
      { "tpidReserved58", "wsm.tpidReserved58",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved59,
      { "tpidReserved59", "wsm.tpidReserved59",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved60,
      { "tpidReserved60", "wsm.tpidReserved60",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved61,
      { "tpidReserved61", "wsm.tpidReserved61",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved62,
      { "tpidReserved62", "wsm.tpidReserved62",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved63,
      { "tpidReserved63", "wsm.tpidReserved63",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved64,
      { "tpidReserved64", "wsm.tpidReserved64",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved65,
      { "tpidReserved65", "wsm.tpidReserved65",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved66,
      { "tpidReserved66", "wsm.tpidReserved66",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved67,
      { "tpidReserved67", "wsm.tpidReserved67",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved68,
      { "tpidReserved68", "wsm.tpidReserved68",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved69,
      { "tpidReserved69", "wsm.tpidReserved69",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved70,
      { "tpidReserved70", "wsm.tpidReserved70",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved71,
      { "tpidReserved71", "wsm.tpidReserved71",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved72,
      { "tpidReserved72", "wsm.tpidReserved72",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved73,
      { "tpidReserved73", "wsm.tpidReserved73",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved74,
      { "tpidReserved74", "wsm.tpidReserved74",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved75,
      { "tpidReserved75", "wsm.tpidReserved75",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved76,
      { "tpidReserved76", "wsm.tpidReserved76",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved77,
      { "tpidReserved77", "wsm.tpidReserved77",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved78,
      { "tpidReserved78", "wsm.tpidReserved78",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved79,
      { "tpidReserved79", "wsm.tpidReserved79",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved80,
      { "tpidReserved80", "wsm.tpidReserved80",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved81,
      { "tpidReserved81", "wsm.tpidReserved81",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved82,
      { "tpidReserved82", "wsm.tpidReserved82",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved83,
      { "tpidReserved83", "wsm.tpidReserved83",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved84,
      { "tpidReserved84", "wsm.tpidReserved84",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved85,
      { "tpidReserved85", "wsm.tpidReserved85",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved86,
      { "tpidReserved86", "wsm.tpidReserved86",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved87,
      { "tpidReserved87", "wsm.tpidReserved87",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved88,
      { "tpidReserved88", "wsm.tpidReserved88",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved89,
      { "tpidReserved89", "wsm.tpidReserved89",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved90,
      { "tpidReserved90", "wsm.tpidReserved90",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved91,
      { "tpidReserved91", "wsm.tpidReserved91",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved92,
      { "tpidReserved92", "wsm.tpidReserved92",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved93,
      { "tpidReserved93", "wsm.tpidReserved93",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved94,
      { "tpidReserved94", "wsm.tpidReserved94",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved95,
      { "tpidReserved95", "wsm.tpidReserved95",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved96,
      { "tpidReserved96", "wsm.tpidReserved96",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved97,
      { "tpidReserved97", "wsm.tpidReserved97",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved98,
      { "tpidReserved98", "wsm.tpidReserved98",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved99,
      { "tpidReserved99", "wsm.tpidReserved99",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved100,
      { "tpidReserved100", "wsm.tpidReserved100",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved101,
      { "tpidReserved101", "wsm.tpidReserved101",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved102,
      { "tpidReserved102", "wsm.tpidReserved102",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved103,
      { "tpidReserved103", "wsm.tpidReserved103",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved104,
      { "tpidReserved104", "wsm.tpidReserved104",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved105,
      { "tpidReserved105", "wsm.tpidReserved105",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved106,
      { "tpidReserved106", "wsm.tpidReserved106",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved107,
      { "tpidReserved107", "wsm.tpidReserved107",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved108,
      { "tpidReserved108", "wsm.tpidReserved108",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved109,
      { "tpidReserved109", "wsm.tpidReserved109",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved110,
      { "tpidReserved110", "wsm.tpidReserved110",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved111,
      { "tpidReserved111", "wsm.tpidReserved111",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved112,
      { "tpidReserved112", "wsm.tpidReserved112",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved113,
      { "tpidReserved113", "wsm.tpidReserved113",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved114,
      { "tpidReserved114", "wsm.tpidReserved114",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved115,
      { "tpidReserved115", "wsm.tpidReserved115",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved116,
      { "tpidReserved116", "wsm.tpidReserved116",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved117,
      { "tpidReserved117", "wsm.tpidReserved117",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved118,
      { "tpidReserved118", "wsm.tpidReserved118",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved119,
      { "tpidReserved119", "wsm.tpidReserved119",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved120,
      { "tpidReserved120", "wsm.tpidReserved120",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved121,
      { "tpidReserved121", "wsm.tpidReserved121",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved122,
      { "tpidReserved122", "wsm.tpidReserved122",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved123,
      { "tpidReserved123", "wsm.tpidReserved123",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved124,
      { "tpidReserved124", "wsm.tpidReserved124",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved125,
      { "tpidReserved125", "wsm.tpidReserved125",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved126,
      { "tpidReserved126", "wsm.tpidReserved126",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_tpidReserved127,
      { "tpidReserved127", "wsm.tpidReserved127",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NoTpidProcessing", HFILL }},
    { &hf_wsm_destAddress,
      { "destAddress", "wsm.destAddress",
        FT_UINT32, BASE_DEC, VALS(wsm_VarLengthNumber_vals), 0,
        "VarLengthNumber", HFILL }},
    { &hf_wsm_tExtensions,
      { "tExtensions", "wsm.tExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ShortMsgTextensions", HFILL }},
    { &hf_wsm_ShortMsgTextensions_item,
      { "ShortMsgTextension", "wsm.ShortMsgTextension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- End of included file: packet-wsm-hfarr.c ---*/
#line 93 "./asn1/wsm/packet-wsm-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_wsm,

/*--- Included file: packet-wsm-ettarr.c ---*/
#line 1 "./asn1/wsm/packet-wsm-ettarr.c"
    &ett_wsm_VarLengthNumber,
    &ett_wsm_Ext1,
    &ett_wsm_Ext2,
    &ett_wsm_Extension,
    &ett_wsm_DataRate80211,
    &ett_wsm_TXpower80211,
    &ett_wsm_ChannelNumber80211,
    &ett_wsm_ShortMsgNpdu,
    &ett_wsm_ShortMsgSubtype,
    &ett_wsm_NoSubtypeProcessing,
    &ett_wsm_NullNetworking,
    &ett_wsm_ShortMsgNextensions,
    &ett_wsm_ShortMsgTpdus,
    &ett_wsm_ShortMsgBcPDU,
    &ett_wsm_ShortMsgTextensions,

/*--- End of included file: packet-wsm-ettarr.c ---*/
#line 99 "./asn1/wsm/packet-wsm-template.c"
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

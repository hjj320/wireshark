/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-wsa.c                                                               */
/* asn2wrs.py -L -S -p wsa -c ./wsa.cnf -s ./packet-wsa-template -D . -O ../.. CITSapplMgmtIDs.asn wee.asn wsa.asn */

/* Input file: packet-wsa-template.c */

#line 1 "./asn1/wsa/packet-wsa-template.c"
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


/*--- Included file: packet-wsa-hf.c ---*/
#line 1 "./asn1/wsa/packet-wsa-hf.c"
static int hf_wsa_SrvAdvMsg_PDU = -1;             /* SrvAdvMsg */
static int hf_wsa_content = -1;                   /* INTEGER_0_127 */
static int hf_wsa_extension = -1;                 /* Ext1 */
static int hf_wsa_content_01 = -1;                /* INTEGER_128_16511 */
static int hf_wsa_extension_01 = -1;              /* Ext2 */
static int hf_wsa_content_02 = -1;                /* INTEGER_16512_2113663 */
static int hf_wsa_extension_02 = -1;              /* Ext3 */
static int hf_wsa_extensionId = -1;               /* RefExt */
static int hf_wsa_value = -1;                     /* T_value */
static int hf_wsa_repeateRate = -1;               /* INTEGER_0_255 */
static int hf_wsa_latitude = -1;                  /* Latitude */
static int hf_wsa_longitude = -1;                 /* Longitude */
static int hf_wsa_elevation = -1;                 /* Elevation */
static int hf_wsa_advertiserIdentifier = -1;      /* UTF8String_SIZE_1_32 */
static int hf_wsa_fillBit = -1;                   /* BIT_STRING_SIZE_3 */
static int hf_wsa_psc = -1;                       /* OCTET_STRING_SIZE_0_31 */
static int hf_wsa_servicePort = -1;               /* INTEGER_0_65535 */
static int hf_wsa_acbeRecord = -1;                /* EdcaParameterRecord */
static int hf_wsa_acbkRecord = -1;                /* EdcaParameterRecord */
static int hf_wsa_acviRecord = -1;                /* EdcaParameterRecord */
static int hf_wsa_acvoRecord = -1;                /* EdcaParameterRecord */
static int hf_wsa_res = -1;                       /* INTEGER_0_1 */
static int hf_wsa_aci = -1;                       /* INTEGER_0_3 */
static int hf_wsa_acm = -1;                       /* INTEGER_0_1 */
static int hf_wsa_aifsn = -1;                     /* INTEGER_0_15 */
static int hf_wsa_ecwMax = -1;                    /* INTEGER_0_1023 */
static int hf_wsa_ecwMin = -1;                    /* INTEGER_0_15 */
static int hf_wsa_txopLimit = -1;                 /* INTEGER_0_65535 */
static int hf_wsa_channelAccess80211 = -1;        /* T_channelAccess80211 */
static int hf_wsa_fill = -1;                      /* BIT_STRING_SIZE_1 */
static int hf_wsa_lat = -1;                       /* INTEGER_M900000000_900000001 */
static int hf_wsa_version = -1;                   /* SrvAdvPrtVersion */
static int hf_wsa_body = -1;                      /* SrvAdvBody */
static int hf_wsa_messageID = -1;                 /* SrvAdvMessageType */
static int hf_wsa_rsvAdvPrtVersion = -1;          /* RsvAdvPrtVersion */
static int hf_wsa_changeCount = -1;               /* SrvAdvChangeCount */
static int hf_wsa_extensions = -1;                /* SrvAdvMsgHeaderExts */
static int hf_wsa_serviceInfos = -1;              /* ServiceInfos */
static int hf_wsa_channelInfos = -1;              /* ChannelInfos */
static int hf_wsa_routingAdvertisement = -1;      /* RoutingAdvertisement */
static int hf_wsa_saID = -1;                      /* SrvAdvID */
static int hf_wsa_contentCount = -1;              /* SrvAdvContentCount */
static int hf_wsa_SrvAdvMsgHeaderExts_item = -1;  /* SrvAdvMsgHeaderExt */
static int hf_wsa_ServiceInfos_item = -1;         /* ServiceInfo */
static int hf_wsa_serviceID = -1;                 /* VarLengthNumber */
static int hf_wsa_channelIndex = -1;              /* ChannelIndex */
static int hf_wsa_chOptions = -1;                 /* ChannelOptions */
static int hf_wsa_mandApp = -1;                   /* MandApp */
static int hf_wsa_serviceProviderPort = -1;       /* ReplyAddress */
static int hf_wsa_extensions_01 = -1;             /* ServiceInfoExts */
static int hf_wsa_ServiceInfoExts_item = -1;      /* ServiceInfoExt */
static int hf_wsa_ChannelInfos_item = -1;         /* ChannelInfo */
static int hf_wsa_operatingClass = -1;            /* OperatingClass80211 */
static int hf_wsa_channelNumber = -1;             /* ChannelNumber80211 */
static int hf_wsa_powerLevel = -1;                /* TXpower80211 */
static int hf_wsa_dataRate = -1;                  /* WsaChInfoDataRate */
static int hf_wsa_extensions_02 = -1;             /* ChInfoOptions */
static int hf_wsa_adaptable = -1;                 /* BIT_STRING_SIZE_1 */
static int hf_wsa_dataRate_01 = -1;               /* INTEGER_0_127 */
static int hf_wsa_option1 = -1;                   /* NULL */
static int hf_wsa_option2 = -1;                   /* NULL */
static int hf_wsa_option3 = -1;                   /* NULL */
static int hf_wsa_option4 = -1;                   /* NULL */
static int hf_wsa_option5 = -1;                   /* NULL */
static int hf_wsa_option6 = -1;                   /* NULL */
static int hf_wsa_option7 = -1;                   /* NULL */
static int hf_wsa_extensions_03 = -1;             /* ChannelInfoExts */
static int hf_wsa_ChannelInfoExts_item = -1;      /* ChannelInfoExt */
static int hf_wsa_lifetime = -1;                  /* RouterLifetime */
static int hf_wsa_ipPrefix = -1;                  /* IpV6Prefix */
static int hf_wsa_ipPrefixLength = -1;            /* IpV6PrefixLength */
static int hf_wsa_defaultGateway = -1;            /* IPv6Address */
static int hf_wsa_primaryDns = -1;                /* IPv6Address */
static int hf_wsa_extensions_04 = -1;             /* RoutAdvertExts */
static int hf_wsa_RoutAdvertExts_item = -1;       /* RoutAdvertExt */

/*--- End of included file: packet-wsa-hf.c ---*/
#line 82 "./asn1/wsa/packet-wsa-template.c"

static int ett_wsa = -1;


/*--- Included file: packet-wsa-ett.c ---*/
#line 1 "./asn1/wsa/packet-wsa-ett.c"
static gint ett_wsa_VarLengthNumber = -1;
static gint ett_wsa_Ext1 = -1;
static gint ett_wsa_Ext2 = -1;
static gint ett_wsa_Extension = -1;
static gint ett_wsa_RepeatRate = -1;
static gint ett_wsa_TwoDLocation = -1;
static gint ett_wsa_ThreeDLocation = -1;
static gint ett_wsa_AdvertiserIdentifier = -1;
static gint ett_wsa_ProviderServiceContext = -1;
static gint ett_wsa_ServicePort = -1;
static gint ett_wsa_EdcaParameterSet = -1;
static gint ett_wsa_EdcaParameterRecord = -1;
static gint ett_wsa_ChannelAccess80211 = -1;
static gint ett_wsa_Latitude = -1;
static gint ett_wsa_SrvAdvMsg = -1;
static gint ett_wsa_SrvAdvPrtVersion = -1;
static gint ett_wsa_SrvAdvBody = -1;
static gint ett_wsa_SrvAdvChangeCount = -1;
static gint ett_wsa_SrvAdvMsgHeaderExts = -1;
static gint ett_wsa_ServiceInfos = -1;
static gint ett_wsa_ServiceInfo = -1;
static gint ett_wsa_ChannelOptions = -1;
static gint ett_wsa_ServiceInfoExts = -1;
static gint ett_wsa_ChannelInfos = -1;
static gint ett_wsa_ChannelInfo = -1;
static gint ett_wsa_WsaChInfoDataRate = -1;
static gint ett_wsa_ChInfoOptions = -1;
static gint ett_wsa_ChannelInfoExts = -1;
static gint ett_wsa_RoutingAdvertisement = -1;
static gint ett_wsa_RoutAdvertExts = -1;

/*--- End of included file: packet-wsa-ett.c ---*/
#line 86 "./asn1/wsa/packet-wsa-template.c"

/*--- Included file: packet-wsa-fn.c ---*/
#line 1 "./asn1/wsa/packet-wsa-fn.c"


static int
dissect_wsa_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_wsa_INTEGER_128_16511(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            128U, 16511U, NULL, FALSE);

  return offset;
}



static int
dissect_wsa_INTEGER_16512_2113663(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            16512U, 2113663U, NULL, FALSE);

  return offset;
}



static int
dissect_wsa_Ext3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            2113664U, 270549119U, NULL, TRUE);

  return offset;
}


static const value_string wsa_Ext2_vals[] = {
  {   0, "content" },
  {   1, "extension" },
  { 0, NULL }
};

static const per_choice_t Ext2_choice[] = {
  {   0, &hf_wsa_content_02      , ASN1_NO_EXTENSIONS     , dissect_wsa_INTEGER_16512_2113663 },
  {   1, &hf_wsa_extension_02    , ASN1_NO_EXTENSIONS     , dissect_wsa_Ext3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_wsa_Ext2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_wsa_Ext2, Ext2_choice,
                                 NULL);

  return offset;
}


static const value_string wsa_Ext1_vals[] = {
  {   0, "content" },
  {   1, "extension" },
  { 0, NULL }
};

static const per_choice_t Ext1_choice[] = {
  {   0, &hf_wsa_content_01      , ASN1_NO_EXTENSIONS     , dissect_wsa_INTEGER_128_16511 },
  {   1, &hf_wsa_extension_01    , ASN1_NO_EXTENSIONS     , dissect_wsa_Ext2 },
  { 0, NULL, 0, NULL }
};

static int
dissect_wsa_Ext1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_wsa_Ext1, Ext1_choice,
                                 NULL);

  return offset;
}


static const value_string wsa_VarLengthNumber_vals[] = {
  {   0, "content" },
  {   1, "extension" },
  { 0, NULL }
};

static const per_choice_t VarLengthNumber_choice[] = {
  {   0, &hf_wsa_content         , ASN1_NO_EXTENSIONS     , dissect_wsa_INTEGER_0_127 },
  {   1, &hf_wsa_extension       , ASN1_NO_EXTENSIONS     , dissect_wsa_Ext1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_wsa_VarLengthNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_wsa_VarLengthNumber, VarLengthNumber_choice,
                                 NULL);

  return offset;
}


static const value_string wsa_RefExt_vals[] = {
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
dissect_wsa_RefExt(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &extensionId, FALSE);

  return offset;
}



static int
dissect_wsa_T_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  switch (extensionId) {
  case 5:
    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_wsa_TwoDLocation);
    break;
  case 6:
    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_wsa_ThreeDLocation);
    break;
  case 7:
    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_wsa_AdvertiserIdentifier);
    break;
  case 8:
    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_wsa_ProviderServiceContext);
    break;
  case 9:
    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_wsa_IPv6Address);
    break;
  case 10:
    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_wsa_ServicePort);
    break;
  case 11:
    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_wsa_ProviderMacAddress);
    break;
  case 12:
    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_wsa_EdcaParameterSet);
    break;
  case 13:
    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_wsa_SecondaryDns);
    break;
  case 14:
    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_wsa_GatewayMacAddress);
    break;
  case 17:
    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_wsa_RepeatRate);
    break;
  case 19:
    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_wsa_RcpiThreshold);
    break;
  case 20:
    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_wsa_WsaCountThreshold);
    break;
  case 21:
    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_wsa_ChannelAccess80211);
    break;
  case 22:
    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_wsa_WsaCountThresholdInterval);
    break;
  default:
    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);
    break;
  }

  return offset;
}


static const per_sequence_t Extension_sequence[] = {
  { &hf_wsa_extensionId     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_RefExt },
  { &hf_wsa_value           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_T_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_Extension, Extension_sequence);

  return offset;
}



static int
dissect_wsa_TXpower80211(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -128, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_wsa_ChannelNumber80211(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_wsa_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t RepeatRate_sequence[] = {
  { &hf_wsa_repeateRate     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_RepeatRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_RepeatRate, RepeatRate_sequence);

  return offset;
}



static int
dissect_wsa_BIT_STRING_SIZE_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 1, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_wsa_INTEGER_M900000000_900000001(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -900000000, 900000001U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Latitude_sequence[] = {
  { &hf_wsa_fill            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_BIT_STRING_SIZE_1 },
  { &hf_wsa_lat             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_INTEGER_M900000000_900000001 },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_Latitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_Latitude, Latitude_sequence);

  return offset;
}



static int
dissect_wsa_Longitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1799999999, 1800000001U, NULL, FALSE);

  return offset;
}


static const per_sequence_t TwoDLocation_sequence[] = {
  { &hf_wsa_latitude        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_Latitude },
  { &hf_wsa_longitude       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_Longitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_TwoDLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_TwoDLocation, TwoDLocation_sequence);

  return offset;
}



static int
dissect_wsa_Elevation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -4096, 61439U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ThreeDLocation_sequence[] = {
  { &hf_wsa_latitude        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_Latitude },
  { &hf_wsa_longitude       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_Longitude },
  { &hf_wsa_elevation       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_Elevation },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_ThreeDLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_ThreeDLocation, ThreeDLocation_sequence);

  return offset;
}



static int
dissect_wsa_UTF8String_SIZE_1_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_UTF8String(tvb, offset, actx, tree, hf_index,
                                          1, 32, FALSE);

  return offset;
}


static const per_sequence_t AdvertiserIdentifier_sequence[] = {
  { &hf_wsa_advertiserIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_UTF8String_SIZE_1_32 },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_AdvertiserIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_AdvertiserIdentifier, AdvertiserIdentifier_sequence);

  return offset;
}



static int
dissect_wsa_BIT_STRING_SIZE_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     3, 3, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_wsa_OCTET_STRING_SIZE_0_31(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       0, 31, FALSE, NULL);

  return offset;
}


static const per_sequence_t ProviderServiceContext_sequence[] = {
  { &hf_wsa_fillBit         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_BIT_STRING_SIZE_3 },
  { &hf_wsa_psc             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_OCTET_STRING_SIZE_0_31 },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_ProviderServiceContext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_ProviderServiceContext, ProviderServiceContext_sequence);

  return offset;
}



static int
dissect_wsa_IPv6Address(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       16, 16, FALSE, NULL);

  return offset;
}



static int
dissect_wsa_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ServicePort_sequence[] = {
  { &hf_wsa_servicePort     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_INTEGER_0_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_ServicePort(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_ServicePort, ServicePort_sequence);

  return offset;
}



static int
dissect_wsa_MACaddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       6, 6, FALSE, NULL);

  return offset;
}



static int
dissect_wsa_ProviderMacAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_wsa_MACaddress(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_wsa_RcpiThreshold(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_wsa_WsaCountThreshold(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_wsa_WsaCountThresholdInterval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_wsa_INTEGER_0_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, FALSE);

  return offset;
}



static int
dissect_wsa_INTEGER_0_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

  return offset;
}



static int
dissect_wsa_INTEGER_0_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}



static int
dissect_wsa_INTEGER_0_1023(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, FALSE);

  return offset;
}


static const per_sequence_t EdcaParameterRecord_sequence[] = {
  { &hf_wsa_res             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_INTEGER_0_1 },
  { &hf_wsa_aci             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_INTEGER_0_3 },
  { &hf_wsa_acm             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_INTEGER_0_1 },
  { &hf_wsa_aifsn           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_INTEGER_0_15 },
  { &hf_wsa_ecwMax          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_INTEGER_0_1023 },
  { &hf_wsa_ecwMin          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_INTEGER_0_15 },
  { &hf_wsa_txopLimit       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_INTEGER_0_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_EdcaParameterRecord(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_EdcaParameterRecord, EdcaParameterRecord_sequence);

  return offset;
}


static const per_sequence_t EdcaParameterSet_sequence[] = {
  { &hf_wsa_acbeRecord      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_EdcaParameterRecord },
  { &hf_wsa_acbkRecord      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_EdcaParameterRecord },
  { &hf_wsa_acviRecord      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_EdcaParameterRecord },
  { &hf_wsa_acvoRecord      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_EdcaParameterRecord },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_EdcaParameterSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_EdcaParameterSet, EdcaParameterSet_sequence);

  return offset;
}


static const value_string wsa_T_channelAccess80211_vals[] = {
  {   0, "continuous" },
  {   1, "alternatingSCH" },
  {   2, "alternatingCCH" },
  { 0, NULL }
};


static int
dissect_wsa_T_channelAccess80211(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ChannelAccess80211_sequence[] = {
  { &hf_wsa_channelAccess80211, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_T_channelAccess80211 },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_ChannelAccess80211(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_ChannelAccess80211, ChannelAccess80211_sequence);

  return offset;
}



static int
dissect_wsa_SecondaryDns(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_wsa_IPv6Address(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_wsa_GatewayMacAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_wsa_MACaddress(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string wsa_SrvAdvMessageType_vals[] = {
  {   0, "saMessage" },
  {   1, "sarMessage" },
  { 0, NULL }
};


static int
dissect_wsa_SrvAdvMessageType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, FALSE);

  return offset;
}



static int
dissect_wsa_RsvAdvPrtVersion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SrvAdvPrtVersion_sequence[] = {
  { &hf_wsa_messageID       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_SrvAdvMessageType },
  { &hf_wsa_rsvAdvPrtVersion, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_RsvAdvPrtVersion },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_SrvAdvPrtVersion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_SrvAdvPrtVersion, SrvAdvPrtVersion_sequence);

  return offset;
}



static int
dissect_wsa_SrvAdvID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}



static int
dissect_wsa_SrvAdvContentCount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SrvAdvChangeCount_sequence[] = {
  { &hf_wsa_saID            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_SrvAdvID },
  { &hf_wsa_contentCount    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_SrvAdvContentCount },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_SrvAdvChangeCount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_SrvAdvChangeCount, SrvAdvChangeCount_sequence);

  return offset;
}



static int
dissect_wsa_SrvAdvMsgHeaderExt(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_wsa_Extension(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t SrvAdvMsgHeaderExts_sequence_of[1] = {
  { &hf_wsa_SrvAdvMsgHeaderExts_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_SrvAdvMsgHeaderExt },
};

static int
dissect_wsa_SrvAdvMsgHeaderExts(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_wsa_SrvAdvMsgHeaderExts, SrvAdvMsgHeaderExts_sequence_of);

  return offset;
}


static const value_string wsa_ChannelIndex_vals[] = {
  {   0, "notUsed" },
  {   1, "firstEntry" },
  { 0, NULL }
};


static int
dissect_wsa_ChannelIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, FALSE);

  return offset;
}



static int
dissect_wsa_MandApp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_wsa_ReplyAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_wsa_ServiceInfoExt(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_wsa_Extension(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t ServiceInfoExts_sequence_of[1] = {
  { &hf_wsa_ServiceInfoExts_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_ServiceInfoExt },
};

static int
dissect_wsa_ServiceInfoExts(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_wsa_ServiceInfoExts, ServiceInfoExts_sequence_of);

  return offset;
}


static const per_sequence_t ChannelOptions_sequence[] = {
  { &hf_wsa_mandApp         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_wsa_MandApp },
  { &hf_wsa_serviceProviderPort, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_wsa_ReplyAddress },
  { &hf_wsa_extensions_01   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_wsa_ServiceInfoExts },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_ChannelOptions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_ChannelOptions, ChannelOptions_sequence);

  return offset;
}


static const per_sequence_t ServiceInfo_sequence[] = {
  { &hf_wsa_serviceID       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_VarLengthNumber },
  { &hf_wsa_channelIndex    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_ChannelIndex },
  { &hf_wsa_chOptions       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_ChannelOptions },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_ServiceInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_ServiceInfo, ServiceInfo_sequence);

  return offset;
}


static const per_sequence_t ServiceInfos_sequence_of[1] = {
  { &hf_wsa_ServiceInfos_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_ServiceInfo },
};

static int
dissect_wsa_ServiceInfos(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_wsa_ServiceInfos, ServiceInfos_sequence_of);

  return offset;
}



static int
dissect_wsa_OperatingClass80211(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t WsaChInfoDataRate_sequence[] = {
  { &hf_wsa_adaptable       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_BIT_STRING_SIZE_1 },
  { &hf_wsa_dataRate_01     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_WsaChInfoDataRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_WsaChInfoDataRate, WsaChInfoDataRate_sequence);

  return offset;
}



static int
dissect_wsa_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_wsa_ChannelInfoExt(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_wsa_Extension(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t ChannelInfoExts_sequence_of[1] = {
  { &hf_wsa_ChannelInfoExts_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_ChannelInfoExt },
};

static int
dissect_wsa_ChannelInfoExts(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_wsa_ChannelInfoExts, ChannelInfoExts_sequence_of);

  return offset;
}


static const per_sequence_t ChInfoOptions_sequence[] = {
  { &hf_wsa_option1         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_wsa_NULL },
  { &hf_wsa_option2         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_wsa_NULL },
  { &hf_wsa_option3         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_wsa_NULL },
  { &hf_wsa_option4         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_wsa_NULL },
  { &hf_wsa_option5         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_wsa_NULL },
  { &hf_wsa_option6         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_wsa_NULL },
  { &hf_wsa_option7         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_wsa_NULL },
  { &hf_wsa_extensions_03   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_wsa_ChannelInfoExts },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_ChInfoOptions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_ChInfoOptions, ChInfoOptions_sequence);

  return offset;
}


static const per_sequence_t ChannelInfo_sequence[] = {
  { &hf_wsa_operatingClass  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_OperatingClass80211 },
  { &hf_wsa_channelNumber   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_ChannelNumber80211 },
  { &hf_wsa_powerLevel      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_TXpower80211 },
  { &hf_wsa_dataRate        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_WsaChInfoDataRate },
  { &hf_wsa_extensions_02   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_ChInfoOptions },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_ChannelInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_ChannelInfo, ChannelInfo_sequence);

  return offset;
}


static const per_sequence_t ChannelInfos_sequence_of[1] = {
  { &hf_wsa_ChannelInfos_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_ChannelInfo },
};

static int
dissect_wsa_ChannelInfos(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_wsa_ChannelInfos, ChannelInfos_sequence_of);

  return offset;
}



static int
dissect_wsa_RouterLifetime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_wsa_IpV6Prefix(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       16, 16, FALSE, NULL);

  return offset;
}



static int
dissect_wsa_IpV6PrefixLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_wsa_RoutAdvertExt(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_wsa_Extension(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RoutAdvertExts_sequence_of[1] = {
  { &hf_wsa_RoutAdvertExts_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_RoutAdvertExt },
};

static int
dissect_wsa_RoutAdvertExts(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_wsa_RoutAdvertExts, RoutAdvertExts_sequence_of);

  return offset;
}


static const per_sequence_t RoutingAdvertisement_sequence[] = {
  { &hf_wsa_lifetime        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_RouterLifetime },
  { &hf_wsa_ipPrefix        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_IpV6Prefix },
  { &hf_wsa_ipPrefixLength  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_IpV6PrefixLength },
  { &hf_wsa_defaultGateway  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_IPv6Address },
  { &hf_wsa_primaryDns      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_IPv6Address },
  { &hf_wsa_extensions_04   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_RoutAdvertExts },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_RoutingAdvertisement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_RoutingAdvertisement, RoutingAdvertisement_sequence);

  return offset;
}


static const per_sequence_t SrvAdvBody_sequence[] = {
  { &hf_wsa_changeCount     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_SrvAdvChangeCount },
  { &hf_wsa_extensions      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_wsa_SrvAdvMsgHeaderExts },
  { &hf_wsa_serviceInfos    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_wsa_ServiceInfos },
  { &hf_wsa_channelInfos    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_wsa_ChannelInfos },
  { &hf_wsa_routingAdvertisement, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_wsa_RoutingAdvertisement },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_SrvAdvBody(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_SrvAdvBody, SrvAdvBody_sequence);

  return offset;
}


static const per_sequence_t SrvAdvMsg_sequence[] = {
  { &hf_wsa_version         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_SrvAdvPrtVersion },
  { &hf_wsa_body            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wsa_SrvAdvBody },
  { NULL, 0, 0, NULL }
};

static int
dissect_wsa_SrvAdvMsg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_wsa_SrvAdvMsg, SrvAdvMsg_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_SrvAdvMsg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_wsa_SrvAdvMsg(tvb, offset, &asn1_ctx, tree, hf_wsa_SrvAdvMsg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-wsa-fn.c ---*/
#line 87 "./asn1/wsa/packet-wsa-template.c"

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

/*--- Included file: packet-wsa-hfarr.c ---*/
#line 1 "./asn1/wsa/packet-wsa-hfarr.c"
    { &hf_wsa_SrvAdvMsg_PDU,
      { "SrvAdvMsg", "wsa.SrvAdvMsg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_content,
      { "content", "wsa.content",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_wsa_extension,
      { "extension", "wsa.extension",
        FT_UINT32, BASE_DEC, VALS(wsa_Ext1_vals), 0,
        "Ext1", HFILL }},
    { &hf_wsa_content_01,
      { "content", "wsa.content",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_128_16511", HFILL }},
    { &hf_wsa_extension_01,
      { "extension", "wsa.extension",
        FT_UINT32, BASE_DEC, VALS(wsa_Ext2_vals), 0,
        "Ext2", HFILL }},
    { &hf_wsa_content_02,
      { "content", "wsa.content",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_16512_2113663", HFILL }},
    { &hf_wsa_extension_02,
      { "extension", "wsa.extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Ext3", HFILL }},
    { &hf_wsa_extensionId,
      { "extensionId", "wsa.extensionId",
        FT_UINT32, BASE_DEC, VALS(wsa_RefExt_vals), 0,
        "RefExt", HFILL }},
    { &hf_wsa_value,
      { "value", "wsa.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_repeateRate,
      { "repeateRate", "wsa.repeateRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_wsa_latitude,
      { "latitude", "wsa.latitude_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_longitude,
      { "longitude", "wsa.longitude",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_elevation,
      { "elevation", "wsa.elevation",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_advertiserIdentifier,
      { "advertiserIdentifier", "wsa.advertiserIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_1_32", HFILL }},
    { &hf_wsa_fillBit,
      { "fillBit", "wsa.fillBit",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_3", HFILL }},
    { &hf_wsa_psc,
      { "psc", "wsa.psc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_0_31", HFILL }},
    { &hf_wsa_servicePort,
      { "servicePort", "wsa.servicePort",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_wsa_acbeRecord,
      { "acbeRecord", "wsa.acbeRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EdcaParameterRecord", HFILL }},
    { &hf_wsa_acbkRecord,
      { "acbkRecord", "wsa.acbkRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EdcaParameterRecord", HFILL }},
    { &hf_wsa_acviRecord,
      { "acviRecord", "wsa.acviRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EdcaParameterRecord", HFILL }},
    { &hf_wsa_acvoRecord,
      { "acvoRecord", "wsa.acvoRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EdcaParameterRecord", HFILL }},
    { &hf_wsa_res,
      { "res", "wsa.res",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_wsa_aci,
      { "aci", "wsa.aci",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_wsa_acm,
      { "acm", "wsa.acm",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_wsa_aifsn,
      { "aifsn", "wsa.aifsn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_wsa_ecwMax,
      { "ecwMax", "wsa.ecwMax",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_wsa_ecwMin,
      { "ecwMin", "wsa.ecwMin",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_wsa_txopLimit,
      { "txopLimit", "wsa.txopLimit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_wsa_channelAccess80211,
      { "channelAccess80211", "wsa.channelAccess80211",
        FT_UINT32, BASE_DEC, VALS(wsa_T_channelAccess80211_vals), 0,
        NULL, HFILL }},
    { &hf_wsa_fill,
      { "fill", "wsa.fill",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1", HFILL }},
    { &hf_wsa_lat,
      { "lat", "wsa.lat",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M900000000_900000001", HFILL }},
    { &hf_wsa_version,
      { "version", "wsa.version_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SrvAdvPrtVersion", HFILL }},
    { &hf_wsa_body,
      { "body", "wsa.body_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SrvAdvBody", HFILL }},
    { &hf_wsa_messageID,
      { "messageID", "wsa.messageID",
        FT_UINT32, BASE_DEC, VALS(wsa_SrvAdvMessageType_vals), 0,
        "SrvAdvMessageType", HFILL }},
    { &hf_wsa_rsvAdvPrtVersion,
      { "rsvAdvPrtVersion", "wsa.rsvAdvPrtVersion",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_changeCount,
      { "changeCount", "wsa.changeCount_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SrvAdvChangeCount", HFILL }},
    { &hf_wsa_extensions,
      { "extensions", "wsa.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SrvAdvMsgHeaderExts", HFILL }},
    { &hf_wsa_serviceInfos,
      { "serviceInfos", "wsa.serviceInfos",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_channelInfos,
      { "channelInfos", "wsa.channelInfos",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_routingAdvertisement,
      { "routingAdvertisement", "wsa.routingAdvertisement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_saID,
      { "saID", "wsa.saID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SrvAdvID", HFILL }},
    { &hf_wsa_contentCount,
      { "contentCount", "wsa.contentCount",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SrvAdvContentCount", HFILL }},
    { &hf_wsa_SrvAdvMsgHeaderExts_item,
      { "SrvAdvMsgHeaderExt", "wsa.SrvAdvMsgHeaderExt_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_ServiceInfos_item,
      { "ServiceInfo", "wsa.ServiceInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_serviceID,
      { "serviceID", "wsa.serviceID",
        FT_UINT32, BASE_DEC, VALS(wsa_VarLengthNumber_vals), 0,
        "VarLengthNumber", HFILL }},
    { &hf_wsa_channelIndex,
      { "channelIndex", "wsa.channelIndex",
        FT_UINT32, BASE_DEC, VALS(wsa_ChannelIndex_vals), 0,
        NULL, HFILL }},
    { &hf_wsa_chOptions,
      { "chOptions", "wsa.chOptions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChannelOptions", HFILL }},
    { &hf_wsa_mandApp,
      { "mandApp", "wsa.mandApp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_serviceProviderPort,
      { "serviceProviderPort", "wsa.serviceProviderPort_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReplyAddress", HFILL }},
    { &hf_wsa_extensions_01,
      { "extensions", "wsa.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ServiceInfoExts", HFILL }},
    { &hf_wsa_ServiceInfoExts_item,
      { "ServiceInfoExt", "wsa.ServiceInfoExt_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_ChannelInfos_item,
      { "ChannelInfo", "wsa.ChannelInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_operatingClass,
      { "operatingClass", "wsa.operatingClass",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OperatingClass80211", HFILL }},
    { &hf_wsa_channelNumber,
      { "channelNumber", "wsa.channelNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ChannelNumber80211", HFILL }},
    { &hf_wsa_powerLevel,
      { "powerLevel", "wsa.powerLevel",
        FT_INT32, BASE_DEC, NULL, 0,
        "TXpower80211", HFILL }},
    { &hf_wsa_dataRate,
      { "dataRate", "wsa.dataRate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "WsaChInfoDataRate", HFILL }},
    { &hf_wsa_extensions_02,
      { "extensions", "wsa.extensions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChInfoOptions", HFILL }},
    { &hf_wsa_adaptable,
      { "adaptable", "wsa.adaptable",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1", HFILL }},
    { &hf_wsa_dataRate_01,
      { "dataRate", "wsa.dataRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_wsa_option1,
      { "option1", "wsa.option1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_option2,
      { "option2", "wsa.option2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_option3,
      { "option3", "wsa.option3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_option4,
      { "option4", "wsa.option4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_option5,
      { "option5", "wsa.option5_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_option6,
      { "option6", "wsa.option6_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_option7,
      { "option7", "wsa.option7_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_extensions_03,
      { "extensions", "wsa.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ChannelInfoExts", HFILL }},
    { &hf_wsa_ChannelInfoExts_item,
      { "ChannelInfoExt", "wsa.ChannelInfoExt_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_wsa_lifetime,
      { "lifetime", "wsa.lifetime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RouterLifetime", HFILL }},
    { &hf_wsa_ipPrefix,
      { "ipPrefix", "wsa.ipPrefix",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IpV6Prefix", HFILL }},
    { &hf_wsa_ipPrefixLength,
      { "ipPrefixLength", "wsa.ipPrefixLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IpV6PrefixLength", HFILL }},
    { &hf_wsa_defaultGateway,
      { "defaultGateway", "wsa.defaultGateway",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IPv6Address", HFILL }},
    { &hf_wsa_primaryDns,
      { "primaryDns", "wsa.primaryDns",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IPv6Address", HFILL }},
    { &hf_wsa_extensions_04,
      { "extensions", "wsa.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RoutAdvertExts", HFILL }},
    { &hf_wsa_RoutAdvertExts_item,
      { "RoutAdvertExt", "wsa.RoutAdvertExt_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- End of included file: packet-wsa-hfarr.c ---*/
#line 107 "./asn1/wsa/packet-wsa-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_wsa,

/*--- Included file: packet-wsa-ettarr.c ---*/
#line 1 "./asn1/wsa/packet-wsa-ettarr.c"
    &ett_wsa_VarLengthNumber,
    &ett_wsa_Ext1,
    &ett_wsa_Ext2,
    &ett_wsa_Extension,
    &ett_wsa_RepeatRate,
    &ett_wsa_TwoDLocation,
    &ett_wsa_ThreeDLocation,
    &ett_wsa_AdvertiserIdentifier,
    &ett_wsa_ProviderServiceContext,
    &ett_wsa_ServicePort,
    &ett_wsa_EdcaParameterSet,
    &ett_wsa_EdcaParameterRecord,
    &ett_wsa_ChannelAccess80211,
    &ett_wsa_Latitude,
    &ett_wsa_SrvAdvMsg,
    &ett_wsa_SrvAdvPrtVersion,
    &ett_wsa_SrvAdvBody,
    &ett_wsa_SrvAdvChangeCount,
    &ett_wsa_SrvAdvMsgHeaderExts,
    &ett_wsa_ServiceInfos,
    &ett_wsa_ServiceInfo,
    &ett_wsa_ChannelOptions,
    &ett_wsa_ServiceInfoExts,
    &ett_wsa_ChannelInfos,
    &ett_wsa_ChannelInfo,
    &ett_wsa_WsaChInfoDataRate,
    &ett_wsa_ChInfoOptions,
    &ett_wsa_ChannelInfoExts,
    &ett_wsa_RoutingAdvertisement,
    &ett_wsa_RoutAdvertExts,

/*--- End of included file: packet-wsa-ettarr.c ---*/
#line 113 "./asn1/wsa/packet-wsa-template.c"
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

/* packet-ieee1609.c
 * Routines for IEEE 1609 (2016, v3) packet dissection
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* References :
 *
 * IEEE Std 1609.2-2016
 *   IEEE Standard for Wireless Accessin Vehicular Environments
 *   -- Security Services for Applications and Management Messages
 * https://standards.ieee.org/findstds/standard/1609.3-2016.html
 *
 * IEEE Std 1609.3-2016
 *   IEEE Standard for Wireless Access in Vehicular Environments (WAVE)
 *   -- Networking Services
 * https://standards.ieee.org/findstds/standard/1609.3-2016.html
 *
 * IEEE Std 1609.12-2016
 *   IEEE Standard for Wireless Access in Vehicular Environments (WAVE)
 *   -- Identifier Allocations
 * https://standards.ieee.org/findstds/standard/1609.12-2016.html
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>

#define WIEID_TRASMIT_POWER_USED 4
#define WIEID_CHANNEL_NUMBER     15
#define WIEID_DATA_RATE          16
#define WIEID_CHANNEL_LOAD       23

/* IEEE 1609.3 - WSM */

typedef struct _wiee_info {
    guint8  id;
    guint8  len;
    guint16 offset;
} wiee_info;

static int proto_ieee1609dot3 = -1;

static int hf_ieee1609dot3_wsmp_n = -1;
static int hf_ieee1609dot3_wsmp_n_subtype = -1;
static int hf_ieee1609dot3_wsmp_n_optind = -1;
static int hf_ieee1609dot3_wsmp_n_version = -1;
static int hf_ieee1609dot3_wsmp_n_wiee = -1;
static int hf_ieee1609dot3_wsmp_n_wiee_txpowused = -1;
static int hf_ieee1609dot3_wsmp_n_wiee_channum = -1;
static int hf_ieee1609dot3_wsmp_n_wiee_rate = -1;
static int hf_ieee1609dot3_wsmp_n_wiee_chanload = -1;
static int hf_ieee1609dot3_wsmp_n_tpid = -1;
static int hf_ieee1609dot3_wsmp_t = -1;
static int hf_ieee1609dot3_wsmp_t_psid = -1;
static int hf_ieee1609dot3_wsmp_t_wsmlen = -1;

static gint ett_ieee1609dot3 = -1;
static gint ett_ieee1609dot3_wsmp_n = -1;
static gint ett_ieee1609dot3_wsmp_n_wiee = -1;
static gint ett_ieee1609dot3_wsmp_t = -1;

static int wiee_hf_table[256];

/* IEEE 1609.2 */

static int proto_ieee1609dot2 = -1;

static int hf_ieee1609dot2_version = -1;
static int hf_ieee1609dot2_content = -1;
static int hf_ieee1609dot2_signed = -1;
static int hf_ieee1609dot2_hashid = -1;
static int hf_ieee1609dot2_datalen = -1;

static gint ett_ieee1609dot2 = -1;
static gint ett_ieee1609dot2_signed = -1;

/* Dissectors */

static dissector_handle_t ieee1609dot2_handle = NULL;

static int
dissect_ieee1609dot3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_item *wsmp_n_item;
    proto_item *wsmp_t_item;
    proto_item *wiee_item;
    proto_tree *ieee1609dot3_tree;
    proto_tree *wsmp_n_tree;
    proto_tree *wsmp_t_tree;
    proto_tree *wiee_tree;
    tvbuff_t   *next_tvb;

    guint16 offset = 0;
    guint16 wsmp_n_len, wiee_len = 0, wsmp_t_len;
    guint16 psid_len = 0, wsmlen_len;
    guint8  subtype, optind, version;
    guint8  nwie = 0;
    guint8  tpid;
    guint64 psid;
    guint16 wsmlen;

    wiee_info wiee[4]; /* max 4 elements */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEEE 1609.3 - WAVE Short Message");
    col_set_str(pinfo->cinfo, COL_INFO, "WAVE Short Message");

    ti = proto_tree_add_item(tree, proto_ieee1609dot3, tvb, 0, -1, ENC_NA);
    ieee1609dot3_tree = proto_item_add_subtree(ti, ett_ieee1609dot3);

    /* WSMP-N-Header */

    subtype = tvb_get_guint8(tvb, offset) & 0xF0; /* 4 bits */
    optind  = tvb_get_guint8(tvb, offset) & 0x08; /* 1 bit  */
    version = tvb_get_guint8(tvb, offset) & 0x07; /* 3 bits */
    offset++;

    if (subtype != 0 || version != 3)
        return 0;

    if (optind) {
        nwie = tvb_get_guint8(tvb, offset);
        wiee_len = 1;
        offset++;

        for (int i = 0; i < nwie; i++) {
            wiee[i].id     = tvb_get_guint8(tvb, offset);
            wiee[i].len    = tvb_get_guint8(tvb, offset + 1);
            wiee[i].offset = offset + 2;
            offset += wiee[i].len + 2;
            wiee_len += wiee[i].len + 2;
        }
    }

    tpid = tvb_get_guint8(tvb, offset);
    offset++;

    wsmp_n_len = offset;

    wsmp_n_item = proto_tree_add_item(ieee1609dot3_tree,
            hf_ieee1609dot3_wsmp_n, tvb, 0, wsmp_n_len, ENC_NA);
    wsmp_n_tree = proto_item_add_subtree(wsmp_n_item,
            ett_ieee1609dot3_wsmp_n);

    proto_tree_add_item(wsmp_n_tree,
            hf_ieee1609dot3_wsmp_n_subtype, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(wsmp_n_tree,
            hf_ieee1609dot3_wsmp_n_optind, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(wsmp_n_tree,
            hf_ieee1609dot3_wsmp_n_version, tvb, 0, 1, ENC_BIG_ENDIAN);

    if (nwie > 0) {
        wiee_item = proto_tree_add_item(wsmp_n_tree,
                hf_ieee1609dot3_wsmp_n_wiee, tvb, 1, wiee_len, ENC_NA);
        wiee_tree = proto_item_add_subtree(wiee_item,
                ett_ieee1609dot3_wsmp_n_wiee);

        for (int i = 0; i < nwie; i++) {
            if (wiee_hf_table[wiee[i].id] >= 0) {
                proto_tree_add_item(wiee_tree,
                        wiee_hf_table[wiee[i].id],
                        tvb, wiee[i].offset, wiee[i].len, ENC_BIG_ENDIAN);
            }
        }
    }

    proto_tree_add_item(wsmp_n_tree,
            hf_ieee1609dot3_wsmp_n_tpid, tvb, offset - 1, 1, ENC_BIG_ENDIAN);

    /* WSMP-T-Header */

    /* Only support TPID == 0 */
    if (tpid > 0) {
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_data_dissector(next_tvb, pinfo, tree);
        return tvb_captured_length(tvb);
    }

    psid = tvb_get_guint8(tvb, offset);
    psid_len = 1;

    if ((psid & 0xF0) == 0xE0)
        psid_len = 4;
    else if ((psid & 0xF0) == 0xC0)
        psid_len = 3;
    else if ((psid & 0xF0) == 0x80)
        psid_len = 2;

    offset += psid_len;

    wsmlen = tvb_get_guint8(tvb, offset);
    wsmlen_len = 1;
    offset++;

    if (wsmlen & 0x80) {
        wsmlen = ((wsmlen & 0x3F) << 8) | tvb_get_guint8(tvb, offset);
        wsmlen_len = 2;
        offset++;
    }

    wsmp_t_len = offset - wsmp_n_len;

    wsmp_t_item = proto_tree_add_item(ieee1609dot3_tree,
            hf_ieee1609dot3_wsmp_t, tvb, wsmp_n_len, wsmp_t_len, ENC_NA);
    wsmp_t_tree = proto_item_add_subtree(wsmp_t_item,
            ett_ieee1609dot3_wsmp_t);

    proto_tree_add_item(wsmp_t_tree,
            hf_ieee1609dot3_wsmp_t_psid, tvb, wsmp_n_len, psid_len, ENC_BIG_ENDIAN);

    proto_tree_add_item(wsmp_t_tree,
            hf_ieee1609dot3_wsmp_t_wsmlen, tvb, wsmp_n_len + psid_len, wsmlen_len, ENC_BIG_ENDIAN);

    next_tvb = tvb_new_subset_length(tvb, offset, wsmlen);
    call_dissector(ieee1609dot2_handle, next_tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

static int
dissect_ieee1609dot2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_item *signed_item;
    proto_tree *ieee1609dot2_tree;
    proto_tree *signed_tree;
    proto_tree *cur_tree;
    tvbuff_t   *next_tvb;

    guint16 offset = 0;
    guint16 datalen = 0;
    guint8 version;
    guint8 content;
   
    version = tvb_get_guint8(tvb, 0);
    if (version != 3)
        return tvb_captured_length(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEEE 1609.2");
    col_set_str(pinfo->cinfo, COL_INFO, "WAVE Secure Service");

    ti = proto_tree_add_item(tree, proto_ieee1609dot2, tvb, 0, -1, ENC_NA);
    ieee1609dot2_tree = proto_item_add_subtree(ti, ett_ieee1609dot2);

    content = tvb_get_guint8(tvb, offset + 1) & 0x7F;
    if (content > 1) {
        next_tvb = tvb_new_subset_remaining(tvb, offset + 1);
        call_data_dissector(next_tvb, pinfo, tree);
        return tvb_captured_length(tvb);
    }

    proto_tree_add_item(ieee1609dot2_tree,
            hf_ieee1609dot2_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(ieee1609dot2_tree,
            hf_ieee1609dot2_content, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    cur_tree = ieee1609dot2_tree;

    /* TODO: decode full secured data and others */
    if (content == 1) {
        signed_item = proto_tree_add_item(ieee1609dot2_tree,
                hf_ieee1609dot2_signed, tvb, offset, -1, ENC_NA);
        signed_tree = proto_item_add_subtree(signed_item,
                ett_ieee1609dot2_signed);

        proto_tree_add_item(signed_tree,
                hf_ieee1609dot2_hashid, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        offset++; /* skip sequence tag */

        proto_tree_add_item(signed_tree,
                hf_ieee1609dot2_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(signed_tree,
                hf_ieee1609dot2_content, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        cur_tree = signed_tree;
    }

    datalen = tvb_get_guint8(tvb, offset);

    if (datalen & 0x80) {
        if ((datalen & 0x7F) == 1) {
            datalen = tvb_get_guint8(tvb, offset + 1);
            proto_tree_add_item(cur_tree,
                    hf_ieee1609dot2_datalen, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
            offset += 2;
        }
        else {
            datalen = tvb_get_ntohs(tvb, offset + 1);
            proto_tree_add_item(cur_tree,
                    hf_ieee1609dot2_datalen, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
            offset += 3;
        }
    }
    else {
        proto_tree_add_item(cur_tree,
                hf_ieee1609dot2_datalen, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    next_tvb = tvb_new_subset_length(tvb, offset, datalen);
    call_data_dissector(next_tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

static void
ieee1609dot3_wsmp_n_wiee_txpowused_value(gchar *result, guint32 val)
{
    g_snprintf(result, ITEM_LABEL_LENGTH, "%d dBm", val - 128);
}

static void
ieee1609dot3_wsmp_n_wiee_rate_value(gchar *result, guint32 val)
{
    g_snprintf(result, ITEM_LABEL_LENGTH, "%.1f Mb/s", val / 2.0f);
}

static void
ieee1609dot3_wsmp_t_psid_value(gchar *result, guint32 val)
{
    /* p-encoding to PSID value by IEEE Std 1609.12-2016 */

    if (val >= 0xE0000000)
        val -= 0xDFDFBF80;
    else if (val >= 0xC00000)
        val -= 0xBFBF80;
    else if (val >= 0x8000)
        val -= 0x7F80;

    if (val > 0xFFFFFF)
        g_snprintf(result, ITEM_LABEL_LENGTH, "%u (0x%02X-%02X-%02X-%02X)",
                val, (val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF);
    else if (val > 0xFFFF)
        g_snprintf(result, ITEM_LABEL_LENGTH, "%u (0x%02X-%02X-%02X)",
                val, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF);
    else if (val > 0xFF)
        g_snprintf(result, ITEM_LABEL_LENGTH, "%u (0x%02X-%02X)",
                val, (val >> 8) & 0xFF, val & 0xFF);
    else
        g_snprintf(result, ITEM_LABEL_LENGTH, "%u (0x%02X)",
                val, val & 0xFF);
}

void
proto_register_ieee1609dot3(void)
{
    static hf_register_info hf[] = {
        { &hf_ieee1609dot3_wsmp_n,
        { "WSMP-N-Header", "ieee1609dot3.wsmpn", FT_NONE, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_ieee1609dot3_wsmp_n_subtype,
        { "Subtype", "ieee1609dot3.wsmpn.subtype", FT_UINT8, BASE_DEC,
            NULL, 0xF0, NULL, HFILL }},
        { &hf_ieee1609dot3_wsmp_n_optind,
        { "Option Indicator", "ieee1609dot3.wsmpn.optind", FT_UINT8, BASE_HEX,
            NULL, 0x08, NULL, HFILL }},
        { &hf_ieee1609dot3_wsmp_n_version,
        { "Version", "ieee1609dot3.version", FT_UINT8, BASE_DEC,
            NULL, 0x07, NULL, HFILL }},
        { &hf_ieee1609dot3_wsmp_n_wiee,
        { "WAVE Information Element Extension", "ieee1609dot3.wsmpn.wiee", FT_NONE, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_ieee1609dot3_wsmp_n_wiee_txpowused,
        { "Transmit Power Used", "ieee1609dot3.wsmpn.wiee.txpowused", FT_UINT8, BASE_CUSTOM,
            CF_FUNC(ieee1609dot3_wsmp_n_wiee_txpowused_value), 0x0, NULL, HFILL }},
        { &hf_ieee1609dot3_wsmp_n_wiee_channum,
        { "Channel Number", "ieee1609dot3.wsmpn.wiee.channum", FT_UINT8, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},
        { &hf_ieee1609dot3_wsmp_n_wiee_rate,
        { "Data Rate", "ieee1609dot3.wsmpn.wiee.rate", FT_UINT8, BASE_CUSTOM,
            CF_FUNC(ieee1609dot3_wsmp_n_wiee_rate_value), 0x0, NULL, HFILL }},
        { &hf_ieee1609dot3_wsmp_n_wiee_chanload,
        { "Channel Load", "ieee1609dot3.wsmpn.wiee.chanload", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_ieee1609dot3_wsmp_n_tpid,
        { "TPID", "ieee1609dot3.wsmpn.tpid", FT_UINT8, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},
        { &hf_ieee1609dot3_wsmp_t,
        { "WSMP-T-Header", "ieee1609dot3.wsmpt", FT_NONE, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_ieee1609dot3_wsmp_t_psid,
        { "PSID", "ieee1609dot3.wsmpt.psid", FT_UINT32, BASE_CUSTOM,
            CF_FUNC(ieee1609dot3_wsmp_t_psid_value), 0x0, NULL, HFILL }},
        { &hf_ieee1609dot3_wsmp_t_wsmlen,
        { "WSM Length", "ieee1609dot3.wsmpt.wsmlen", FT_UINT16, BASE_DEC,
            NULL, 0x3FFF, NULL, HFILL }},
	};

    static gint *ett[] = {
        &ett_ieee1609dot3,
        &ett_ieee1609dot3_wsmp_n,
        &ett_ieee1609dot3_wsmp_n_wiee,
        &ett_ieee1609dot3_wsmp_t,
    };

    proto_ieee1609dot3 = proto_register_protocol(
            "IEEE 1609.3 - WAVE Short Message Protocol",
            "IEEE 1609.3", /* short name */
            "ieee1609dot3" /* abbrev     */
            );

    proto_register_field_array(proto_ieee1609dot3, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("ieee1609dot3", dissect_ieee1609dot3, proto_ieee1609dot3);

    memset(wiee_hf_table, -1, sizeof(wiee_hf_table));

    wiee_hf_table[WIEID_TRASMIT_POWER_USED] = hf_ieee1609dot3_wsmp_n_wiee_txpowused;
    wiee_hf_table[WIEID_CHANNEL_NUMBER] = hf_ieee1609dot3_wsmp_n_wiee_channum;
    wiee_hf_table[WIEID_DATA_RATE] = hf_ieee1609dot3_wsmp_n_wiee_rate;
    wiee_hf_table[WIEID_CHANNEL_LOAD] = hf_ieee1609dot3_wsmp_n_wiee_chanload;
}

static const value_string ieee1609dot2_content_vals[] = {
    { 0, "Unsecured Data" },
    { 1, "Signed Data" },
    { 2, "Encrypted Data" },
    { 3, "Signed CertificateRequest" },
    { 0, NULL }
};

static const value_string ieee1609dot2_hashid_vals[] = {
    { 0, "SHA-256" },
    { 0, NULL }
};

void
proto_register_ieee1609dot2(void)
{
    static hf_register_info hf[] = {
        { &hf_ieee1609dot2_version,
        { "Protocol Version", "ieee1609dot2.version", FT_UINT8, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},
        { &hf_ieee1609dot2_content,
        { "Content", "ieee1609dot2.content", FT_UINT8, BASE_DEC,
            VALS(ieee1609dot2_content_vals), 0x7F, NULL, HFILL }},
        { &hf_ieee1609dot2_signed,
        { "Signed Data", "ieee1609dot2.signed", FT_NONE, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_ieee1609dot2_hashid,
        { "Hash Algorithm", "ieee1609dot2.hashid", FT_UINT8, BASE_DEC,
            VALS(ieee1609dot2_hashid_vals), 0x0, NULL, HFILL }},
        { &hf_ieee1609dot2_datalen,
        { "Data Length", "ieee1609dot2.datalen", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL }}
	};

    static gint *ett[] = {
        &ett_ieee1609dot2,
        &ett_ieee1609dot2_signed,
    };

    proto_ieee1609dot2 = proto_register_protocol(
            "IEEE 1609.2 - WAVE Secure Service",
            "IEEE 1609.2", /* short name */
            "ieee1609dot2" /* abbrev     */
            );

    proto_register_field_array(proto_ieee1609dot2, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("ieee1609dot2", dissect_ieee1609dot2, proto_ieee1609dot2);
}

void
proto_reg_handoff_ieee1609dot3(void)
{
    dissector_handle_t ieee1609dot3_handle = find_dissector("ieee1609dot3");
    dissector_add_uint("ethertype", ETHERTYPE_WSMP, ieee1609dot3_handle);

    ieee1609dot2_handle = find_dissector_add_dependency("ieee1609dot2", proto_ieee1609dot3);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

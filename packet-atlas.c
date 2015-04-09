#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <glib.h>
#include <epan/packet.h>

#include <string.h>

/* TODO: fix this. This length may be variable. */
#define TCP_HEADER_LEN 20

#define PROTO_TAG_ATLAS    "ATLAS TDAQ"

/* 
   . Type ID (4 bytes)
   . Transaction ID (4 bytes)
   . Data size (4 bytes)
*/
#define ATLAS_HEADER_LEN 12

/* Each of the fields is 4 bytes long */
#define ATLAS_FIELD_LEN 4

/* Byte offsets of each field */
#define TYPE_ID_OFFSET 0
#define TRANS_ID_OFFSET 4
#define DATA_SIZE_OFFSET 8
#define EVENT_ID_OFFSET 12
#define FRAGS_OFFSET 16

/* Protocol constants */
#define REQUEST_ID 0x20dfdc00 
#define RESPONSE_ID 0x21dfdc00


/* Wireshark ID of the ATLAS protocol */
static int proto_atlas = -1;

static dissector_handle_t atlas_handle;
static void dissect_atlas(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static int atlas_proto_num = 6;

/* The following hf_* variables are used to hold the Wireshark IDs of
 * our header fields; they are filled out when we call
 * proto_register_field_array() in proto_register_atlas()
 */
static gint hf_type_id = -1;
static gint hf_trans_id = -1;
static gint hf_data_size = -1;
static gint hf_event_id = -1;
static gint hf_frag_count = -1;
static gint hf_max_frag = -1;
static gint hf_min_frag = -1;

/* ID of the subtree that we are creating. */
static gint ett_atlas = -1;

void proto_reg_handoff_atlas(void)
{
    static gboolean initialized=FALSE;

    /*  Dissect all TCP packets. */
    if (!initialized) {
        initialized = TRUE;        
        atlas_handle = create_dissector_handle(dissect_atlas, proto_atlas);
        dissector_add_uint("ip.proto", atlas_proto_num, atlas_handle);
    }

}

void proto_register_atlas(void)
{
    /* A header field is something you can search/filter on.
     * 
     * We create a structure to register our fields. It consists of an
     * array of hf_register_info structures, each of which are of the format
     * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
     */
    static hf_register_info hf[] = {
        
        { &hf_type_id,
        { "ATLAS Type ID", "atlas.type", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_trans_id,
        { "ATLAS Transaction ID", "atlas.trans_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_data_size,
        { "Data size", "atlas.size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        /* For Request messages only */
        { &hf_event_id,
        { "ATLAS Event ID", "atlas.event_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},    

        { &hf_frag_count,
        { "ATLAS Fragment Count", "atlas.frag_count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_max_frag,
        { "ATLAS Max Fragment", "atlas.max_frag", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_min_frag,
        { "ATLAS Min Fragment", "atlas.min_frag", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_atlas
    };
    
    proto_atlas = proto_register_protocol(PROTO_TAG_ATLAS, "ATLAS TDAQ", "atlas");
    proto_register_field_array(proto_atlas, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("atlas", dissect_atlas, proto_atlas);
}
    

static guint32 from_little_endian(guint32 num)
{
    #define SHIFTL(i, x) (x << (8*i))
    #define SHIFTR(i, x) (x >> (8*i))
    #define BYTE(i, n) (SHIFTR(i, (n & SHIFTL(i, 0xff))))

    return SHIFTL(3, BYTE(0, num)) |
           SHIFTL(2, BYTE(1, num)) |
           SHIFTL(1, BYTE(2, num)) |
           BYTE(3, num);
}

static void get_min_max_frags(tvbuff_t *tvb, guint32 frag_offset, guint32 frag_count,
                              guint32 *max_frag, guint32 *max_frag_offset,
                              guint32 *min_frag, guint32 *min_frag_offset)
{
    guint32 current_frag, current_frag_offset, i;
    *max_frag = 0;
    *min_frag = *max_frag - 1;
    for(i = 0; i < frag_count; ++i)
    {
        current_frag_offset = frag_offset + (i<<2);
        current_frag = from_little_endian(tvb_get_ntohl(tvb, current_frag_offset));
        if(current_frag >= *max_frag)
        {
            *max_frag = current_frag;
            *max_frag_offset = current_frag_offset;
        }
        if(current_frag <= *min_frag)
        {
            *min_frag = current_frag;
            *min_frag_offset = current_frag_offset;
        }
    }
}

static void dissect_atlas(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Our data starts where the TCP header ends. */
    gint base_offset = TCP_HEADER_LEN;
    guint32 packet_len, typeID, trans_id, data_size,
            event_id, frag_bytes, frag_count,
            max_frag, max_frag_offset,
            min_frag, min_frag_offset;
    tvbuff_t *tcptvb;
    char type_str[20] = "";



    /* Update the Protocol column. Also, clear Info column. */
    if(check_col(pinfo->cinfo,COL_INFO))
        col_clear(pinfo->cinfo,COL_INFO);
    if(check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_ATLAS);

    typeID = from_little_endian(tvb_get_ntohl(tvb, base_offset));
    trans_id = from_little_endian(tvb_get_ntohl(tvb, base_offset+ATLAS_FIELD_LEN));
    data_size = from_little_endian(tvb_get_ntohl(tvb, base_offset+2*ATLAS_FIELD_LEN));
    packet_len = ATLAS_HEADER_LEN + data_size;

    if(typeID == REQUEST_ID)
        strcpy(type_str, "1 (Request)");
    else if (typeID == RESPONSE_ID)
        strcpy(type_str, "2 (Response)");
    else
        strcpy(type_str, "Unknown");

    if (check_col(pinfo->cinfo, COL_INFO))
        col_add_fstr(pinfo->cinfo, COL_INFO, "ATLAS Type ID: %s; ATLAS Transaction ID: %u", type_str, trans_id);

    /* This is where we register the protocol tree items: Type ID, Transaction ID and so forth. 
       Items added will be shown in the packet pane (when clicking a given packet).    
    */
    if(tree) 
    {
        proto_item *ti = NULL;
        proto_tree *atlas_tree = NULL;

        ti = proto_tree_add_item(tree, proto_atlas, tvb, base_offset, packet_len, ENC_NA);
        atlas_tree = proto_item_add_subtree(ti, ett_atlas);

        /* Type ID */
        proto_tree_add_item(atlas_tree, hf_type_id, tvb, base_offset+TYPE_ID_OFFSET, ATLAS_FIELD_LEN, ENC_NA);

        /* Transaction ID */
        proto_tree_add_item(atlas_tree, hf_trans_id, tvb, base_offset+TRANS_ID_OFFSET, ATLAS_FIELD_LEN, ENC_LITTLE_ENDIAN);

        /* Data size (in bytes) */
        proto_tree_add_item(atlas_tree, hf_data_size, tvb, base_offset+DATA_SIZE_OFFSET, ATLAS_FIELD_LEN, ENC_LITTLE_ENDIAN);

        if(typeID == REQUEST_ID)
        {
            /* Event ID */
            proto_tree_add_item(atlas_tree, hf_event_id, tvb, base_offset+EVENT_ID_OFFSET, ATLAS_FIELD_LEN, ENC_LITTLE_ENDIAN);

            /* Fragment count */
            /* -4 since the Event ID counts as data. */
            frag_bytes = data_size - ATLAS_FIELD_LEN;
            frag_count = frag_bytes / ATLAS_FIELD_LEN;
            proto_tree_add_uint(atlas_tree, hf_frag_count, tvb, base_offset+FRAGS_OFFSET, frag_bytes, frag_count);

            /* Min/Max fragments */
            get_min_max_frags(tvb, base_offset+FRAGS_OFFSET, frag_count, &max_frag, &max_frag_offset, &min_frag, &min_frag_offset);
            proto_tree_add_uint(atlas_tree, hf_max_frag, tvb, max_frag_offset, ATLAS_FIELD_LEN, max_frag);
            proto_tree_add_uint(atlas_tree, hf_min_frag, tvb, min_frag_offset, ATLAS_FIELD_LEN, min_frag);
        }

    }
}    

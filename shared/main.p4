/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define MAX_HOPS 6

const bit<16> TYPE_MYTUNNEL = 0x1212;
const bit<16> TYPE_IPV4 = 0x800;
 
const bit<5> VALIDATION_HEADER_VALID = 7;
const bit<32> PATH_SUM_THRESHOLD = 50; // Example threshold value

//HEADERS 

typedef bit<9>  egressSpec_t;
typedef bit<32> switchID_t;
typedef bit<32> qdepth_t;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;    // Differentiated Services Code Point (DSCP)
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

// header ipv4_option_t {
//     bit<1> copyFlag;
//     bit<2> optClass;
//     bit<5> option;
//     bit<8> optionLength;
// }

// header mri_t {
//     bit<16>  count;
// }

// header switch_t {
//     switchID_t  swid;
//     qdepth_t    qdepth;
// }

// tunnel header to handle tunneling
header myTunnel_t {  
    bit<16> tunnel_id; //match specific tunnel id   (assume int > 0)
}

// header validation_t {
//     bit<5> isValid;
//     mri_t mri;
//     switch_t[MAX_HOPS] swtraces;
//     bit<32> cumulative_tunnel_sum;  // <-- NEW
// }

// NOTE: Added new header type to headers struct
struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    // ipv4_option_t      ipv4_option;
    myTunnel_t myTunnel;
    // validation_t validation;
}





//INIT METADATA

struct ingress_metadata_t {
    bit<16>  count;
}

struct parser_metadata_t {
    bit<16>  remaining;
}

struct metadata {
    //used to implement MRI
    // ingress_metadata_t   ingress_metadata;
    // parser_metadata_t   parser_metadata;
    bool add_tunnel;
}

//END METADATA





//PARSER

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(meta.add_tunnel) {
            true : parse_tunnel;
            default : accept;
        }
    }

    state parse_tunnel {
        packet.extract(hdr.myTunnel);
        transition accept;  //accept transition for now

    }
}

//CHECKSUM VERIFICATION
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


//INGRESS PROCESSING
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_tunnel_match(bit<16> tunnel_id) {
        meta.add_tunnel = true;
        hdr.myTunnel.setValid();
        hdr.myTunnel.tunnel_id = tunnel_id;
    }

    
    table ipv4_tunnel_forward {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.ipv4.diffserv: exact;
        }
        actions = {
            ipv4_tunnel_match;
            drop;
        }
        size = 1024;
        default_action = drop();
    
    }

    action tunnel_forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    table intermediate_tables {
        key = {
            hdr.myTunnel.tunnel_id: exact;
        }
        actions = {
            // add actions as needed
            tunnel_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    
    apply {
        log_msg("log");
        if(!meta.add_tunnel){
            ipv4_tunnel_forward.apply();
            intermediate_tables.apply();
        }else{
            //intermediate tunnel
            intermediate_tables.apply();
        }
    }
}

//EGRESS PROCESSING

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    //TODO
    //fare una tabella che dato un tunnel_id fa fowarding verso un determinato switch in output
    //inizializzare un validation header

    
    
    apply {
        
    }
}

//CHECKSUM COMPUTATION
control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {}
}

//DEPARSER
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.myTunnel);
    }
}

//SWITCH
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

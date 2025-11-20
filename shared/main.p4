/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define MAX_HOPS 6

const bit<8> PROTO_MYTUNNEL = 0x88;
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
    bit<16> proto_id;
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
        transition select(hdr.ipv4.protocol) {
            PROTO_MYTUNNEL: parse_myTunnel;
            default: accept;
        }
    }

    state parse_myTunnel {
        packet.extract(hdr.myTunnel);
        transition accept;
    }
}

//CHECKSUM VERIFICATION
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action tunnel_ingress(bit<16> tunnel_id, bit<9> port, bit<48> dstAddr) {
        hdr.myTunnel.setValid();
        hdr.myTunnel.tunnel_id = tunnel_id; 

        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        
        hdr.myTunnel.proto_id = (bit<16>)hdr.ipv4.protocol;

        hdr.ipv4.protocol = PROTO_MYTUNNEL; // defined as 0x88 previously
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4; // 4 bytes is correct (2 for proto + 2 for id)
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        standard_metadata.egress_spec = port;
    }
    
    table ipv4_tunnel_forward {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.ipv4.diffserv: exact;
        }
        actions = {
            tunnel_ingress;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    action tunnel_forward(bit<9> port){
        standard_metadata.egress_spec = port;
    }

    action tunnel_decapsulate(bit<9> port){
        // Restore Protocol
        hdr.ipv4.protocol = (bit<8>)hdr.myTunnel.proto_id;
        
        // Fix Length
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 4;
        
        // Remove Header
        hdr.myTunnel.setInvalid();
        
        standard_metadata.egress_spec = port;
    }

    table intermediate_tables {
        key = {
            hdr.myTunnel.tunnel_id: exact;
        }
        actions = {
            tunnel_forward;
            tunnel_decapsulate;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        // Process standard IPv4 packets (entering the tunnel)
        if(!hdr.myTunnel.isValid() && hdr.ipv4.isValid()){
            ipv4_tunnel_forward.apply(); 
        }

        // Process Tunneled packets (transit or exiting)
        if(hdr.myTunnel.isValid()){
            intermediate_tables.apply();
        }
    }
}


//EGRESS PROCESSING

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    
    
    apply {
        
    }
}

//CHECKSUM COMPUTATION
control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply{
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol, // This will now reflect PROTO_MYTUNNEL if tunneled
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
     }
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

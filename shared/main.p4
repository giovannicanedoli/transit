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

header ipv4_option_t {
    bit<1> copyFlag;
    bit<2> optClass;
    bit<5> option;
    bit<8> optionLength;
}

header mri_t {
    bit<16>  count;
}

header switch_t {
    switchID_t  swid;
    qdepth_t    qdepth;
}

// tunnel header to handle tunneling
header myTunnel_t {  
    bit<16> tunnel_id; //match specific tunnel id   (assume int > 0)
}

header validation_t {
    bit<5> isValid;
    mri_t mri;
    switch_t[MAX_HOPS] swtraces;
    bit<32> cumulative_tunnel_sum;  // <-- NEW
}

// NOTE: Added new header type to headers struct
struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    ipv4_option_t      ipv4_option;
    // myTunnel_t myTunnel;
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
    ingress_metadata_t   ingress_metadata;
    parser_metadata_t   parser_metadata;
}

//END METADATA





//PARSER

// TODO: Update the parser to parse the myTunnel header as well
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
        verify(hdr.ipv4.ihl >= 5, error.IPHeaderTooShort);
        transition select(hdr.ipv4.ihl) {
            5             : accept;
            default       : parse_ipv4_option;
        }
    }

    state parse_ipv4_option {
        //used to parse ipv4 options (used for the path validation)
        packet.extract(hdr.ipv4_option);
        transition select(hdr.ipv4_option.option){
            IPV4_OPTION_MRI: parse_mri;
            default: accept;
        }

    }

    state parse_tunnel {
        packet.extract(hdr.myTunnel);
        //go to the transition parse_mri only if there is the validation header
        transition select(hdr.myTunnel.isValid()){
            1: parse_mri;
            default: accept;
        }
    }

    state parse_mri {
        packet.extract(hdr.mri);
        meta.parser_metadata.remaining = hdr.mri.count;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default: parse_swtrace; 
        }
    }

    state parse_swtrace {
        /*
        * TODO: Add logic to:
        * - Extract hdr.swtraces.next.
        * - Decrement meta.parser_metadata.remaining by 1
        * - Select on the value of meta.parser_metadata.remaining
        *   - If the value is equal to 0, accept.
        *   - Otherwise, transition to parse_swtrace.
        */
        packet.extract(hdr.swtraces.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining  - 1;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default: parse_swtrace;
        }
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

    action ipv4_tunnel_match(bit<16> tunnel_id, bit<9>  output_port) {
        //I wanna obtain the value associated to that tuple
        hdr.myTunnel.setValid();
        hdr.myTunnel.dst_id = tunnel_id;
        //add a validation header
        // hdr.validation.setValid();
        // hdr.validation.isValid = VALIDATION_HEADER_VALID;
        //forward packet to output_port
        standard_metadata.egress_spec = output_port;
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
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    //forward packet to output_port given a tunnel_id both as input and output
    action forward_based_on_tunnelid(bit<16> tunnel_id, bit<9> output_port) {
        //validation header initialization
        hdr.validation.setValid();
        hdr.validation.isValid = VALIDATION_HEADER_VALID;
        hdr.validation.mri.count = 0; //initialize the mri count to 0
        hdr.validation.cumulative_tunnel_sum = hdr.myTunnel.tunnel_id; // initialize cumulative sum
        standard_metadata.egress_spec = output_port;
    }

    table transit_switch_table {
        key = {
            hdr.myTunnel.tunnel_id: exact;
        }
        actions = {
            forward_based_on_tunnelid;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        //execute only if there is no validation header
        if(!hdr.myTunnel.isValid()){
            ipv4_tunnel_forward.apply();
        }else{
            transit_switch_table.apply();
        }
    }
}

//EGRESS PROCESSING

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
                    
    action add_swtrace(switchID_t swid) {
        hdr.validation.mri.count = hdr.validation.mri.count + 1;
        hdr.validation.swtraces[0].setValid();
        hdr.validation.swtraces[0].swid = swid;
        hdr.validation.swtraces[0].qdepth = (qdepth_t)standard_metadata.deq_qdepth;

        // Update cumulative_tunnel_sum
        hdr.validation.cumulative_tunnel_sum = hdr.validation.cumulative_tunnel_sum + hdr.myTunnel.tunnel_id;

        hdr.ipv4.ihl = hdr.ipv4.ihl + 2;
        hdr.ipv4_option.optionLength = hdr.ipv4_option.optionLength + 8;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8;
    }

    table swtrace {
        actions        = {
            add_swtrace;
            NoAction;
        }

        default_action =  NoAction();
    }

    action validate_path_sum() {
    if (hdr.validation.cumulative_tunnel_sum > PATH_SUM_THRESHOLD) {
        mark_to_drop(standard_metadata);
        }
    }

    table path_sum_validation {
        actions        = {
            validate_path_sum;
            NoAction;
        }

        default_action =  NoAction();
    }


    apply { 
        if(hdr.validation.isValid()){
            swtrace.apply();
            path_sum_validation.apply();    
        }
    }
}

//CHECKSUM COMPUTATION
control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
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
              hdr.ipv4.protocol,
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
        packet.emit(hdr.ipv4_option);
        // TODO: emit myTunnel header as well
        if (hdr.myTunnel.isValid()) {
            packet.emit(hdr.myTunnel);
        }
        if(hdr.validation.isValid()){
            packet.emit(hdr.validation);   
        }
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

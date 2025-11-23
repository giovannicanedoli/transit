/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define MAX_HOPS 6

const bit<8> PROTO_MYTUNNEL = 0x88;
const bit<16> TYPE_IPV4 = 0x800;
const bit<5>  IPV4_OPTION_MRI = 31;
 
const bit<5> VALIDATION_HEADER_VALID = 7;

//HEADERS 

typedef bit<9>  egressSpec_t;
typedef bit<16> switchID_t;
typedef bit<16> qdepth_t;


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

// tunnel header to handle tunneling
header myTunnel_t {  
    bit<16> proto_id;
    bit<16> tunnel_id;
}

header mri_t {
    bit<16>  count;
}


header validation_t {
    switchID_t swid;
    qdepth_t    qdepth;
}

// NOTE: Added new header type to headers struct
struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    ipv4_option_t ipv4_option;
    myTunnel_t myTunnel;
    mri_t mri;
    validation_t[MAX_HOPS] validation;
}


//INIT METADATA

struct metadata {
    bit<16> remaining;
    bit<16> threshold;
}

//END METADATA



error { IPHeaderTooShort }


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

    // state parse_ipv4 {
    //     packet.extract(hdr.ipv4);
    //     transition select(hdr.ipv4.protocol) {
    //         PROTO_MYTUNNEL: parse_myTunnel;
    //         default: accept;
    //     }
    // }

    // state parse_myTunnel {
    //     packet.extract(hdr.myTunnel);
    //     transition parse_ipv4_option;
    // }

    state parse_ipv4{
        packet.extract(hdr.ipv4);
        verify(hdr.ipv4.ihl >= 5, error.IPHeaderTooShort);
        transition select(hdr.ipv4.ihl) {
            5             : accept;
            default       : parse_ipv4_option;
        }
    }

    state parse_ipv4_option {
        packet.extract(hdr.ipv4_option);
        transition select(hdr.ipv4.protocol){
            PROTO_MYTUNNEL: parse_myTunnel;
            default: accept;
        }
    }

    state parse_myTunnel {
        packet.extract(hdr.myTunnel);
        transition select(hdr.ipv4_option.option){
            IPV4_OPTION_MRI: parse_mri;
            default: accept;
        }
    }

    state parse_mri {
        packet.extract(hdr.mri);
        meta.remaining = hdr.mri.count;
        transition select(meta.remaining) {
            0 : accept;
            default: parse_validation; 
        } 
    }

    state parse_validation{
        packet.extract(hdr.validation.next);
        meta.remaining = meta.remaining -1;
        transition select(meta.remaining){
            0 : accept;
            default: parse_validation;
        }
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
        log_msg("forwording_msg");
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
    
    action setup_mri(){
        log_msg("SETUP MRI HEADER!");
        hdr.mri.setValid();
        hdr.mri.count = 0;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 2;
    }

    action add_mri(switchID_t swid) {
        /* 1. UPDATE PATH SUM (Proof of Transit) */
        hdr.mri.count = hdr.mri.count + swid;
        log_msg("MRI count updated to: {}", { hdr.mri.count });

        /* 2. PUSH FRONT (The Fix)
        Shift existing headers down to make room at index 0.
        e.g., validation[0] -> validation[1]
        */
        hdr.validation.push_front(1);

        /* 3. WRITE DATA TO NEW HEAD (Index 0) */
        hdr.validation[0].setValid();
        hdr.validation[0].swid = swid;
        hdr.validation[0].qdepth = (qdepth_t)standard_metadata.deq_qdepth;

        /* 4. UPDATE IPV4 LENGTHS
        We added 8 bytes of data (sizeof switchID_t + sizeof qdepth_t),
        so we must update the IP header to reflect the larger packet size.
        */
        hdr.ipv4.ihl = hdr.ipv4.ihl + 2; // 2 words (8 bytes)
        hdr.ipv4_option.optionLength = hdr.ipv4_option.optionLength + 8;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8;
    }

    action pop_validation_stack() {
        /* STEP 1: CALCULATE SIZE TO REMOVE 
           We need to know exactly how many bytes to strip.
           - Each trace in the stack is 8 bytes.
           - The mri header (count) is 2 bytes.
           - The ipv4_option header is 2 bytes.
           - Total static overhead = 4 bytes.
        */
        bit<16> stack_bytes = (bit<16>)hdr.mri.count * 8;
        bit<16> total_removal_bytes = stack_bytes + 4;

        /* STEP 2: RESTORE IPV4 LENGTHS */
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - total_removal_bytes;
        
        // IHL is measured in 32-bit (4-byte) words. 
        // We divide by 4 (right shift 2) to subtract the correct amount from IHL.
        hdr.ipv4.ihl = hdr.ipv4.ihl - (bit<4>)(total_removal_bytes >> 2);

        /* STEP 3: INVALIDATE HEADERS */
        hdr.mri.setInvalid();
        hdr.ipv4_option.setInvalid();

        /* STEP 4: CLEAR THE STACK 
           pop_front(N) shifts the stack N times. 
           Using MAX_HOPS ensures the entire stack is wiped clean.
        */
        hdr.validation.pop_front(MAX_HOPS);
        
        log_msg("Validation stack popped. IP restored.");
    }

    action set_threshold(bit<16> threshold){
        meta.threshold = threshold;
    }

    table set_mri {
        actions = {
            add_mri;
            NoAction;
        }
        default_action = NoAction();
    }

    table load_threshold{
        actions = {
            set_threshold;
            NoAction;
        }
        default_action = NoAction(); // Or drop() if you want strict security
    }
    
    
    apply {
        if(hdr.myTunnel.isValid() && !hdr.mri.isValid()){
            log_msg("EXECUTING");
            setup_mri();
        }
        if(hdr.mri.isValid()){
            set_mri.apply();
        }
        if(!hdr.myTunnel.isValid()){
            load_threshold.apply();
            log_msg("THRESHOLD VALUE SET SUCCESSFULLY!");
            if(hdr.mri.count <= meta.threshold){
                log_msg("PROOF VALID. Expected <= {}, Got {}", {meta.threshold, hdr.mri.count});
                pop_validation_stack();
            }else{
                log_msg("PROOF FAILED. Dropping.");
                mark_to_drop(standard_metadata);
            }
        }
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
        packet.emit(hdr.ipv4_option);
        packet.emit(hdr.myTunnel);
        packet.emit(hdr.mri);
        packet.emit(hdr.validation);
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

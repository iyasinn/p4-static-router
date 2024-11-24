
// // checksum and lets see if the ip packet is valid
// // also i want something for simply converting a buffer to

#include "protocol.h"
#include "util.h"
#include "utils.h"

bool ip_checksum_valid(sr_ip_hdr_t *ip) {

  int checksum = cksum(ip, sizeof(sr_ip_hdr_t));
}
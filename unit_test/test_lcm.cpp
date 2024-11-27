#include <_types/_uint32_t.h>
#include <arpa/inet.h>
#include <bitset>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

using namespace std;

struct Result {
  uint32_t count;
  uint32_t dst;
};

Result lcm(vector<uint32_t> &entries, uint32_t ip) {

  /* Make a mask*/
  uint32_t allOnes = 0xFFFFFFFF;
  int mask_size = 24;
  uint32_t mask = allOnes << 8;

  // 11111111110000
  uint32_t dest_answer = 0;
  int LCM_size = 0;

  for (auto entry : entries) {
    uint32_t masked_entry_addr = entry & mask;
    uint32_t masked_dest_addr = ip & mask;

    int count = 0;

    for (int i = 0; i < 32; i++) {
      int shift = (31 - i); // index we look at

      if (((mask >> shift) & 1) == 0) {
        break;
      }

      if (((masked_entry_addr >> shift) & 1) ==
          ((masked_dest_addr >> shift) & 1)) {
        count += 1;
      } else {
        break;
      }
    }

    if (count > LCM_size) {
      LCM_size = count;
      dest_answer = entry;
    }
  }

  Result result;
  result.dst = dest_answer;
  result.count = LCM_size;

  return result;
}

Result lcmStringMethod(vector<uint32_t> &entries, uint32_t ip) {
  uint32_t allOnes = 0xFFFFFFFF;
  int mask_size = 24;
  uint32_t mask = allOnes << 8;

  string dest_answer;
  int LCM_size = 0;

  for (auto entry : entries) {
    string masked_entry_str = bitset<32>(entry & mask).to_string();
    string masked_dest_str = bitset<32>(ip & mask).to_string();

    int count = 0;
    for (int i = 0; i < mask_size; i++) {
      if (masked_entry_str[i] == masked_dest_str[i]) {
        count += 1;
      } else {
        break;
      }
    }

    if (count > LCM_size) {
      LCM_size = count;
      dest_answer = masked_entry_str;
    }
  }

  Result result;
  result.dst = bitset<32>(dest_answer).to_ulong();
  result.count = LCM_size;

  return result;
}

void testNoMatchingPrefixes() {
  vector<uint32_t> entries = {0xFF000000, 0xFA000000,
                              0xF5000000}; // Different high-order bits
  uint32_t ip = 0x00000000; // Completely different high-order bits
  Result result = lcm(entries, ip);

  if (result.count == 0 && result.dst == 0) {
    cout << "Test 1 passed: No matching prefixes found." << endl;
  } else {
    cout << "Test 1 failed: Expected count = 0 and dst = 0, but got count = "
         << result.count << " and dst = " << result.dst << endl;
  }
}

void testLongestPrefixMatchWithFirstEntry() {
  vector<uint32_t> entries = {
      0xC0A80000, 0xC0A00000,
      0xC0000000};          // 192.168.0.0, 192.160.0.0, 192.0.0.0
  uint32_t ip = 0xC0A80F01; // 192.168.0.1
  Result result = lcm(entries, ip);

  if (result.count == 20 && result.dst == 0xC0A80000) {
    cout << "Test 2 passed: Longest prefix match is with the second entry."
         << endl;
  } else {
    cout << "Test 2 failed: Expected count = 24 and dst = 0xC0A80000, but got "
            "count = "
         << result.count << " and dst = " << hex << result.dst << endl;
  }
}

void testMatchWithSecond() {
  vector<uint32_t> entries = {
      0xC0A80000, 0xC0A80F00,
      0xC0000000};          // 192.168.0.0, 192.160.0.0, 192.0.0.0
  uint32_t ip = 0xC0A80F01; // 192.168.0.1
  Result result = lcm(entries, ip);

  if (result.count == 24 && result.dst == 0xC0A80F00) {
    cout << "Test 2 passed: Longest prefix match is with the first entry."
         << endl;
  } else {
    cout << "Test 2 failed: Expected count = 24 and dst = 0xC0A80000, but got "
            "count = "
         << result.count << " and dst = " << hex << result.dst << endl;
  }
}

int main() {
  testNoMatchingPrefixes();
  testLongestPrefixMatchWithFirstEntry();
  testMatchWithSecond();
  return 0;
}
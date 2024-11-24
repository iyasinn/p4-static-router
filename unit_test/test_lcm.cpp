#include <_types/_uint32_t.h>
#include <arpa/inet.h>
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
  uint32_t allOnes = 0xFFFFFFFF;
  int mask_size = 24;
  uint32_t mask = allOnes << 8;

  uint32_t dest_answer = 0;
  int LCM_size = 0;

  for (auto entry : entries) {
    uint32_t masked_entry_addr = entry & mask;
    uint32_t masked_dest_addr = ip & mask;

    int count = 0;
    for (int i = 0; i < mask_size; i++) {
      int shift = (31 - i);

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
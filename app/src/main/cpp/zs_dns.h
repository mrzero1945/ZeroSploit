// DNS query parsing and poisoned-answer construction for the DNS spoofing
// module.
//
// Kept out of zs_helper.cpp for the same reason as zs_sniff.cpp: the helper
// cannot be compiled for the host, and a spoofed answer is judged on exact
// bytes. Tests here compare those bytes directly instead of inferring them from
// whether a phone happened to load the page.
//
// This module produces a DNS *message* only. Wrapping it in UDP/IP and putting
// it on the wire is zs_helper.cpp's job, so nothing here needs a socket.
#ifndef ZS_DNS_H
#define ZS_DNS_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// A parsed question from a DNS query. Holds the offsets of the question
// section rather than a re-encoded copy, because the answer has to echo the
// question byte for byte.
struct DnsQuery {
  uint16_t id = 0;
  std::string name;      // dotted form, e.g. "example.com"
  int qtype = 0;         // 1 = A, 28 = AAAA, 5 = CNAME
  size_t questionAt = 0; // offset of the name within the DNS message
  size_t questionLen = 0;

  // Returns false for anything that is not a well-formed query this module
  // could answer: too short, QR set, no question, a compression pointer inside
  // the name, or a name over the length limits.
  bool parse(const uint8_t* d, size_t len);
};

// Builds the DNS message for a reply that resolves `q.name` to `answerIp`.
//
// The question section is copied straight out of the original message rather
// than re-encoded from the dotted name, because a resolver that gets back a
// question it did not ask discards the answer as a mismatch.
//
// Returns false and leaves `out` untouched if answerIp is not a dotted-quad or
// the question lies outside `query`; the caller must not transmit a partially
// built reply.
bool buildDnsAnswer(const DnsQuery& q, const uint8_t* query, size_t qlen,
                    const std::string& answerIp, std::vector<uint8_t>* out);

// True when `name` is the hostname the operator asked to spoof. Case-insensitive
// because DNS names are, and a device capitalising its own query is not a
// different question.
bool dnsNameMatches(const std::string& name, const std::string& want);

#endif  // ZS_DNS_H

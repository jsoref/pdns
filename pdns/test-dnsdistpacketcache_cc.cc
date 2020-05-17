#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "ednscookies.hh"
#include "ednsoptions.hh"
#include "ednspadding.hh"
#include "ednssubnet.hh"
#include "dnsdist.hh"
#include "iputils.hh"
#include "dnswriter.hh"
#include "dnsdist-cache.hh"
#include "gettime.hh"
#include "packetcache.hh"

BOOST_AUTO_TEST_SUITE(test_dnsdistpacketcache_cc)

BOOST_AUTO_TEST_CASE(test_PacketCacheSimple) {
  const size_t maxEntries = 150000;
  DNSDistPacketCache PC(maxEntries, 86400, 1);
  BOOST_CHECK_EQUAL(PC.getSize(), 0U);
  struct timespec queryTime;
  gettime(&queryTime);  // does not have to be accurate ("realTime") in tests

  size_t counter=0;
  size_t skipped=0;
  ComboAddress remote;
  bool dnssecOK = false;
  try {
    for(counter = 0; counter < 100000; ++counter) {
      DNSName a=DNSName(std::to_string(counter))+DNSName(" hello");
      BOOST_CHECK_EQUAL(DNSName(a.toString()), a);

      vector<uint8_t> query;
      DNSPacketWriter pwQ(query, a, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;

      vector<uint8_t> response;
      DNSPacketWriter pwR(response, a, QType::A, QClass::IN, 0);
      pwR.getHeader()->rd = 1;
      pwR.getHeader()->ra = 1;
      pwR.getHeader()->qr = 1;
      pwR.getHeader()->id = pwQ.getHeader()->id;
      pwR.startRecord(a, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
      pwR.xfr32BitInt(0x01020304);
      pwR.commit();
      uint16_t responseLen = response.size();

      char responseBuf[4096];
      uint16_t responseBufSize = sizeof(responseBuf);
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      auto dh = reinterpret_cast<dnsheader*>(query.data());
      DNSQuestion dq(&a, QType::A, QClass::IN, 0, &remote, &remote, dh, query.size(), query.size(), false, &queryTime);
      bool found = PC.get(dq, a.wirelength(), 0, responseBuf, &responseBufSize, &key, subnet, dnssecOK);
      BOOST_CHECK_EQUAL(found, false);
      BOOST_CHECK(!subnet);

      PC.insert(key, subnet, *(getFlagsFromDNSHeader(dh)), dnssecOK, a, QType::A, QClass::IN, (const char*) response.data(), responseLen, false, 0, boost::none);

      found = PC.get(dq, a.wirelength(), pwR.getHeader()->id, responseBuf, &responseBufSize, &key, subnet, dnssecOK, 0, true);
      if (found == true) {
        BOOST_CHECK_EQUAL(responseBufSize, responseLen);
        int match = memcmp(responseBuf, response.data(), responseLen);
        BOOST_CHECK_EQUAL(match, 0);
        BOOST_CHECK(!subnet);
      }
      else {
        skipped++;
      }
    }

    BOOST_CHECK_EQUAL(skipped, PC.getInsertCollisions());
    BOOST_CHECK_EQUAL(PC.getSize(), counter - skipped);

    size_t deleted=0;
    size_t delcounter=0;
    for(delcounter=0; delcounter < counter/1000; ++delcounter) {
      DNSName a=DNSName(std::to_string(delcounter))+DNSName(" hello");
      vector<uint8_t> query;
      DNSPacketWriter pwQ(query, a, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;
      char responseBuf[4096];
      uint16_t responseBufSize = sizeof(responseBuf);
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dq(&a, QType::A, QClass::IN, 0, &remote, &remote, (struct dnsheader*) query.data(), query.size(), query.size(), false, &queryTime);
      bool found = PC.get(dq, a.wirelength(), 0, responseBuf, &responseBufSize, &key, subnet, dnssecOK);
      if (found == true) {
        auto removed = PC.expungeByName(a);
        BOOST_CHECK_EQUAL(removed, 1U);
        deleted += removed;
      }
    }
    BOOST_CHECK_EQUAL(PC.getSize(), counter - skipped - deleted);

    size_t matches=0;
    vector<DNSResourceRecord> entry;
    size_t expected=counter-skipped-deleted;
    for(; delcounter < counter; ++delcounter) {
      DNSName a(DNSName(std::to_string(delcounter))+DNSName(" hello"));
      vector<uint8_t> query;
      DNSPacketWriter pwQ(query, a, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;
      uint16_t len = query.size();
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      char response[4096];
      uint16_t responseSize = sizeof(response);
      DNSQuestion dq(&a, QType::A, QClass::IN, 0, &remote, &remote, (struct dnsheader*) query.data(), len, query.size(), false, &queryTime);
      if(PC.get(dq, a.wirelength(), pwQ.getHeader()->id, response, &responseSize, &key, subnet, dnssecOK)) {
        matches++;
      }
    }

    /* in the unlikely event that the test took so long that the entries did expire.. */
    auto expired = PC.purgeExpired();
    BOOST_CHECK_EQUAL(matches + expired, expected);

    auto remaining = PC.getSize();
    auto removed = PC.expungeByName(DNSName(" hello"), QType::ANY, true);
    BOOST_CHECK_EQUAL(PC.getSize(), 0U);
    BOOST_CHECK_EQUAL(removed, remaining);
  }
  catch(PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheServFailTTL) {
  const size_t maxEntries = 150000;
  DNSDistPacketCache PC(maxEntries, 86400, 1);
  struct timespec queryTime;
  gettime(&queryTime);  // does not have to be accurate ("realTime") in tests

  ComboAddress remote;
  bool dnssecOK = false;
  try {
    DNSName a = DNSName("servfail");
    BOOST_CHECK_EQUAL(DNSName(a.toString()), a);

    vector<uint8_t> query;
    DNSPacketWriter pwQ(query, a, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;

    vector<uint8_t> response;
    DNSPacketWriter pwR(response, a, QType::A, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 0;
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rcode = RCode::ServFail;
    pwR.getHeader()->id = pwQ.getHeader()->id;
    pwR.commit();
    uint16_t responseLen = response.size();

    char responseBuf[4096];
    uint16_t responseBufSize = sizeof(responseBuf);
    uint32_t key = 0;
    boost::optional<Netmask> subnet;
    auto dh = reinterpret_cast<dnsheader*>(query.data());
    DNSQuestion dq(&a, QType::A, QClass::IN, 0, &remote, &remote, dh, query.size(), query.size(), false, &queryTime);
    bool found = PC.get(dq, a.wirelength(), 0, responseBuf, &responseBufSize, &key, subnet, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    // Insert with failure-TTL of 0 (-> should not enter cache).
    PC.insert(key, subnet, *(getFlagsFromDNSHeader(dh)), dnssecOK, a, QType::A, QClass::IN, (const char*) response.data(), responseLen, false, RCode::ServFail, boost::optional<uint32_t>(0));
    found = PC.get(dq, a.wirelength(), pwR.getHeader()->id, responseBuf, &responseBufSize, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    // Insert with failure-TTL non-zero (-> should enter cache).
    PC.insert(key, subnet, *(getFlagsFromDNSHeader(dh)), dnssecOK, a, QType::A, QClass::IN, (const char*) response.data(), responseLen, false, RCode::ServFail, boost::optional<uint32_t>(300));
    found = PC.get(dq, a.wirelength(), pwR.getHeader()->id, responseBuf, &responseBufSize, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_CHECK(!subnet);
  }
  catch(PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheNoDataTTL) {
  const size_t maxEntries = 150000;
  DNSDistPacketCache PC(maxEntries, /* maxTTL */ 86400, /* minTTL */ 1, /* tempFailureTTL */ 60, /* maxNegativeTTL */ 1);

  struct timespec queryTime;
  gettime(&queryTime);  // does not have to be accurate ("realTime") in tests

  ComboAddress remote;
  bool dnssecOK = false;
  try {
    DNSName name("nodata");
    vector<uint8_t> query;
    DNSPacketWriter pwQ(query, name, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;

    vector<uint8_t> response;
    DNSPacketWriter pwR(response, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 0;
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rcode = RCode::NoError;
    pwR.getHeader()->id = pwQ.getHeader()->id;
    pwR.commit();
    pwR.startRecord(name, QType::SOA, 86400, QClass::IN, DNSResourceRecord::AUTHORITY);
    pwR.commit();
    pwR.addOpt(4096, 0, 0);
    pwR.commit();

    uint16_t responseLen = response.size();

    char responseBuf[4096];
    uint16_t responseBufSize = sizeof(responseBuf);
    uint32_t key = 0;
    boost::optional<Netmask> subnet;
    auto dh = reinterpret_cast<dnsheader*>(query.data());
    DNSQuestion dq(&name, QType::A, QClass::IN, 0, &remote, &remote, dh, query.size(), query.size(), false, &queryTime);
    bool found = PC.get(dq, name.wirelength(), 0, responseBuf, &responseBufSize, &key, subnet, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    PC.insert(key, subnet, *(getFlagsFromDNSHeader(dh)), dnssecOK, name, QType::A, QClass::IN, reinterpret_cast<const char*>(response.data()), responseLen, false, RCode::NoError, boost::none);
    found = PC.get(dq, name.wirelength(), pwR.getHeader()->id, responseBuf, &responseBufSize, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_CHECK(!subnet);

    sleep(2);
    /* it should have expired by now */
    found = PC.get(dq, name.wirelength(), pwR.getHeader()->id, responseBuf, &responseBufSize, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);
  }
  catch(const PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheNXDomainTTL) {
  const size_t maxEntries = 150000;
  DNSDistPacketCache PC(maxEntries, /* maxTTL */ 86400, /* minTTL */ 1, /* tempFailureTTL */ 60, /* maxNegativeTTL */ 1);

  struct timespec queryTime;
  gettime(&queryTime);  // does not have to be accurate ("realTime") in tests

  ComboAddress remote;
  bool dnssecOK = false;
  try {
    DNSName name("nxdomain");
    vector<uint8_t> query;
    DNSPacketWriter pwQ(query, name, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;

    vector<uint8_t> response;
    DNSPacketWriter pwR(response, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 0;
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rcode = RCode::NXDomain;
    pwR.getHeader()->id = pwQ.getHeader()->id;
    pwR.commit();
    pwR.startRecord(name, QType::SOA, 86400, QClass::IN, DNSResourceRecord::AUTHORITY);
    pwR.commit();
    pwR.addOpt(4096, 0, 0);
    pwR.commit();

    uint16_t responseLen = response.size();

    char responseBuf[4096];
    uint16_t responseBufSize = sizeof(responseBuf);
    uint32_t key = 0;
    boost::optional<Netmask> subnet;
    auto dh = reinterpret_cast<dnsheader*>(query.data());
    DNSQuestion dq(&name, QType::A, QClass::IN, 0, &remote, &remote, dh, query.size(), query.size(), false, &queryTime);
    bool found = PC.get(dq, name.wirelength(), 0, responseBuf, &responseBufSize, &key, subnet, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    PC.insert(key, subnet, *(getFlagsFromDNSHeader(dh)), dnssecOK, name, QType::A, QClass::IN, reinterpret_cast<const char*>(response.data()), responseLen, false, RCode::NXDomain, boost::none);
    found = PC.get(dq, name.wirelength(), pwR.getHeader()->id, responseBuf, &responseBufSize, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_CHECK(!subnet);

    sleep(2);
    /* it should have expired by now */
    found = PC.get(dq, name.wirelength(), pwR.getHeader()->id, responseBuf, &responseBufSize, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);
  }
  catch(const PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
}

static DNSDistPacketCache g_PC(500000);

static void threadMangler(unsigned int offset)
{
  struct timespec queryTime;
  gettime(&queryTime);  // does not have to be accurate ("realTime") in tests
  try {
    ComboAddress remote;
    bool dnssecOK = false;
    for(unsigned int counter=0; counter < 100000; ++counter) {
      DNSName a=DNSName("hello ")+DNSName(std::to_string(counter+offset));
      vector<uint8_t> query;
      DNSPacketWriter pwQ(query, a, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;

      vector<uint8_t> response;
      DNSPacketWriter pwR(response, a, QType::A, QClass::IN, 0);
      pwR.getHeader()->rd = 1;
      pwR.getHeader()->ra = 1;
      pwR.getHeader()->qr = 1;
      pwR.getHeader()->id = pwQ.getHeader()->id;
      pwR.startRecord(a, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER);
      pwR.xfr32BitInt(0x01020304);
      pwR.commit();
      uint16_t responseLen = response.size();

      char responseBuf[4096];
      uint16_t responseBufSize = sizeof(responseBuf);
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      auto dh = reinterpret_cast<dnsheader*>(query.data());
      DNSQuestion dq(&a, QType::A, QClass::IN, 0, &remote, &remote, dh, query.size(), query.size(), false, &queryTime);
      g_PC.get(dq, a.wirelength(), 0, responseBuf, &responseBufSize, &key, subnet, dnssecOK);

      g_PC.insert(key, subnet, *(getFlagsFromDNSHeader(dh)), dnssecOK, a, QType::A, QClass::IN, (const char*) response.data(), responseLen, false, 0, boost::none);
    }
  }
  catch(PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
}

AtomicCounter g_missing;

static void threadReader(unsigned int offset)
{
  bool dnssecOK = false;
  struct timespec queryTime;
  gettime(&queryTime);  // does not have to be accurate ("realTime") in tests
  try
  {
    vector<DNSResourceRecord> entry;
    ComboAddress remote;
    for(unsigned int counter=0; counter < 100000; ++counter) {
      DNSName a=DNSName("hello ")+DNSName(std::to_string(counter+offset));
      vector<uint8_t> query;
      DNSPacketWriter pwQ(query, a, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;

      char responseBuf[4096];
      uint16_t responseBufSize = sizeof(responseBuf);
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dq(&a, QType::A, QClass::IN, 0, &remote, &remote, (struct dnsheader*) query.data(), query.size(), query.size(), false, &queryTime);
      bool found = g_PC.get(dq, a.wirelength(), 0, responseBuf, &responseBufSize, &key, subnet, dnssecOK);
      if (!found) {
	g_missing++;
      }
    }
  }
  catch(PDNSException& e) {
    cerr<<"Had error in threadReader: "<<e.reason<<endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheThreaded) {
  try {
    std::vector<std::thread> threads;
    for (int i = 0; i < 4; ++i) {
      threads.push_back(std::thread(threadMangler, i*1000000UL));
    }

    for (auto& t : threads) {
      t.join();
    }

    threads.clear();

    BOOST_CHECK_EQUAL(g_PC.getSize() + g_PC.getDeferredInserts() + g_PC.getInsertCollisions(), 400000U);
    BOOST_CHECK_SMALL(1.0*g_PC.getInsertCollisions(), 10000.0);

    for (int i = 0; i < 4; ++i) {
      threads.push_back(std::thread(threadReader, i*1000000UL));
    }

    for (auto& t : threads) {
      t.join();
    }

    BOOST_CHECK((g_PC.getDeferredInserts() + g_PC.getDeferredLookups() + g_PC.getInsertCollisions()) >= g_missing);
  }
  catch(PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }

}

BOOST_AUTO_TEST_CASE(test_PCEDNSOptions) {
  const size_t maxEntries = 150000;
  DNSDistPacketCache PC(maxEntries, 86400, 1, 60, 3600, 60, true /* don't age */, 1, true, true);
  PC.setCookieHashing(false);
  BOOST_CHECK_EQUAL(PC.getSize(), 0U);

  DNSName qname("www.powerdns.com.");
  uint16_t qtype = QType::AAAA;

  DNSPacketWriter::optvect_t ednsOptions;
  EDNSSubnetOpts ecsOpt;
  EDNSCookiesOpt cookiesOpt;

  std::map<std::string, std::tuple<std::vector<uint8_t>, bool, std::vector<uint8_t>>> queriesResponsesStore;

  auto addEntry = [&PC, &queriesResponsesStore, qname, qtype](const std::string& entryName, boost::optional<DNSPacketWriter::optvect_t> ednsOpts, const std::string& response, bool shouldCollide=false) {
    const ComboAddress remote("192.0.2.1");
    bool dnssecOK = false;
    char responseBuf[4096];
    uint16_t responseBufSize = sizeof(responseBuf);
    uint32_t key;
    boost::optional<Netmask> subnetOut;
    struct timespec queryTime;
    gettime(&queryTime);

    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, QClass::IN, 0);
    pw.getHeader()->rd = 1;
    pw.getHeader()->id = 0x42;
    if (ednsOpts) {
      pw.addOpt(512, 0, 0, *ednsOpts);
      dnssecOK = true;
    }
    pw.commit();

    vector<uint8_t> responseVect;
    DNSPacketWriter pwR(responseVect, qname, qtype, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->id = 0x42;
    pwR.startRecord(qname, QType::TXT, 100, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrText('"' + response + '"');
    pwR.commit();
    if (dnssecOK) {
      pwR.addOpt(512, 0, 0);
      dnssecOK = true;
    }
    pwR.commit();

    DNSQuestion dq(&qname, QType::AAAA, QClass::IN, 0, &remote, &remote, pw.getHeader(), query.size(), query.size(), false, &queryTime);

    bool found = PC.get(dq, qname.wirelength(), 0x42, responseBuf, &responseBufSize, &key, subnetOut, dnssecOK);

    if (shouldCollide && !found) {
      cerr<<"Error, the entry "<<entryName<<" should match an existing one and didn't"<<endl;
      BOOST_CHECK(false);
    }
    else if (!shouldCollide && found) {
      cerr<<"Error, the entry "<<entryName<<" should NOT match an existing one and matched "<<std::string(responseBuf, responseBufSize)<<endl;
      BOOST_CHECK(false);
    }

    if (!found) {
      PC.insert(key, subnetOut, *(getFlagsFromDNSHeader(pw.getHeader())), dnssecOK, qname, qtype, QClass::IN, reinterpret_cast<const char*>(responseVect.data()), responseVect.size(), false, RCode::NoError, boost::none);
    }

    queriesResponsesStore[entryName] = std::make_tuple(query, dnssecOK, responseVect);
  };

  auto checkEntryMatches = [&PC, &queriesResponsesStore, qname, qtype](const std::string& entryName, const std::string& otherEntry="") {
    const ComboAddress remote("192.0.2.1");
    char responseBuf[4096];
    uint16_t responseBufSize = sizeof(responseBuf);
    uint32_t key;
    boost::optional<Netmask> subnetOut;
    struct timespec queryTime;
    gettime(&queryTime);

    const std::vector<uint8_t>& query = std::get<0>(queriesResponsesStore.at(entryName));
    bool dnssecOK = std::get<1>(queriesResponsesStore.at(entryName));
    const std::vector<uint8_t>& expectedResponse = std::get<2>(queriesResponsesStore.at(otherEntry.empty() ? entryName : otherEntry));

    DNSQuestion dq(&qname, QType::AAAA, QClass::IN, 0, &remote, &remote, const_cast<dnsheader*>(reinterpret_cast<const dnsheader*>(query.data())), query.size(), query.size(), false, &queryTime);

    bool found = PC.get(dq, qname.wirelength(), 0x42, responseBuf, &responseBufSize, &key, subnetOut, dnssecOK);
    if (found) {
      if (responseBufSize != expectedResponse.size()) {
        cerr<<"Error, the size of the entry found for "<<entryName<<" ("<<responseBufSize<<") does not match the size of the expected one "<<expectedResponse.size()<<endl;
        BOOST_CHECK(false);
        return;
      }
      if (memcmp(responseBuf, expectedResponse.data(), responseBufSize) != 0) {
        cerr<<"Error, the entry found for "<<entryName<<" does not match the expected one"<<endl;
        BOOST_CHECK(false);
        return;
      }
    }
    else {
      cerr<<"Error, the entry for "<<entryName<<" (key "<<key<<") has not been found in the packet cache"<<endl;
      BOOST_CHECK(false);
    }
  };

  addEntry("query without EDNS", boost::none, "response to no-EDNS query");
  addEntry("query with EDNS but no options", DNSPacketWriter::optvect_t(), "response to EDNS query with no options");

  ecsOpt.source = Netmask("192.0.2.1/32");
  ednsOptions = { std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(ecsOpt)) };
  addEntry("query with ECS 192.0.2.1/32", ednsOptions, "response to EDNS query with ECS 192.0.2.1/32");

  ecsOpt.source = Netmask("192.0.2.2/32");
  ednsOptions = { std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(ecsOpt)) };
  addEntry("query with ECS 192.0.2.2/32", ednsOptions, "response to EDNS query with ECS 192.0.2.2/32");

  ecsOpt.source = Netmask("0.0.0.0/0");
  ednsOptions = { std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(ecsOpt)) };
  addEntry("query with ECS 0.0.0.0/0", ednsOptions, "response to EDNS query with ECS 0.0.0.0/0");

  cookiesOpt.client = string("deadbeef");
  cookiesOpt.server = string("deadbeef");
  ednsOptions = { std::make_pair(EDNSOptionCode::COOKIE, makeEDNSCookiesOptString(cookiesOpt)) };
  addEntry("query with EDNS cookie of deadbeef", ednsOptions, "response to EDNS query with cookie of deadbeef");

  cookiesOpt.client = string("deadbeef");
  cookiesOpt.server = string("deadbeefdeadc0de");
  ednsOptions = { std::make_pair(EDNSOptionCode::COOKIE, makeEDNSCookiesOptString(cookiesOpt)) };
  /* should collide with the previous one, since we skip cookies */
  addEntry("query with EDNS cookie of deadbeefdeadc0de", ednsOptions, "response to EDNS query with cookie of deadbeefdeadc0de", true);

  ednsOptions = { std::make_pair(EDNSOptionCode::PADDING, makeEDNSPaddingOptString(4)) };
  addEntry("query with EDNS padding of 4 bytes", ednsOptions, "response to EDNS query with padding of 4 bytes");

  ednsOptions = { std::make_pair(EDNSOptionCode::PADDING, makeEDNSPaddingOptString(5)) };
  /* should collide with the previous one since we skip padding */
  addEntry("query with EDNS padding of 5 bytes", ednsOptions, "response to EDNS query with padding of 5 bytes", true);

  cookiesOpt.client = string("deadbeef");
  cookiesOpt.server = string("deadbeef");
  ednsOptions = { std::make_pair(EDNSOptionCode::COOKIE, makeEDNSCookiesOptString(cookiesOpt)), std::make_pair(EDNSOptionCode::PADDING, makeEDNSPaddingOptString(4)) };
  addEntry("query with EDNS cookie of deadbeef plus padding of 4 bytes", ednsOptions, "response to EDNS query with a cookie of deadbeef and a padding of 4 bytes");

  cookiesOpt.client = string("deadbeef");
  cookiesOpt.server = string("deadbeefdeadc0de");
  ednsOptions = { std::make_pair(EDNSOptionCode::COOKIE, makeEDNSCookiesOptString(cookiesOpt)), std::make_pair(EDNSOptionCode::PADDING, makeEDNSPaddingOptString(5)) };
  /* should match the previous since the content (and size!) of both cookies and padding are ignored */
  addEntry("query with EDNS cookie of deadbeefdeadc0de plus padding of 5 bytes", ednsOptions, "response to EDNS query with a cookie of deadbeefdeadc0de and a padding of 5 bytes", true);

  checkEntryMatches("query without EDNS");
  checkEntryMatches("query with EDNS but no options");
  checkEntryMatches("query with ECS 192.0.2.1/32");
  checkEntryMatches("query with ECS 192.0.2.2/32");
  checkEntryMatches("query with EDNS cookie of deadbeef");
  checkEntryMatches("query with EDNS cookie of deadbeefdeadc0de", "query with EDNS cookie of deadbeef");
  checkEntryMatches("query with EDNS padding of 4 bytes");
  checkEntryMatches("query with EDNS padding of 5 bytes", "query with EDNS padding of 4 bytes");
  checkEntryMatches("query with EDNS cookie of deadbeef plus padding of 4 bytes");
  checkEntryMatches("query with EDNS cookie of deadbeefdeadc0de plus padding of 5 bytes", "query with EDNS cookie of deadbeef plus padding of 4 bytes");

    /* ****************** */
  /* we now clear the cache and set it in "hash cookies" mode */
  PC.expunge(0);
  PC.setCookieHashing(true);
  BOOST_CHECK_EQUAL(PC.getSize(), 0U);
  queriesResponsesStore.clear();

  addEntry("query without EDNS", boost::none, "response to no-EDNS query");
  addEntry("query with EDNS but no options", DNSPacketWriter::optvect_t(), "response to EDNS query with no options");

  ecsOpt.source = Netmask("192.0.2.1/32");
  ednsOptions = { std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(ecsOpt)) };
  addEntry("query with ECS 192.0.2.1/32", ednsOptions, "response to EDNS query with ECS 192.0.2.1/32");

  ecsOpt.source = Netmask("192.0.2.2/32");
  ednsOptions = { std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(ecsOpt)) };
  addEntry("query with ECS 192.0.2.2/32", ednsOptions, "response to EDNS query with ECS 192.0.2.2/32");

  ecsOpt.source = Netmask("0.0.0.0/0");
  ednsOptions = { std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(ecsOpt)) };
  addEntry("query with ECS 0.0.0.0/0", ednsOptions, "response to EDNS query with ECS 0.0.0.0/0");

  cookiesOpt.client = string("deadbeef");
  cookiesOpt.server = string("deadbeef");
  ednsOptions = { std::make_pair(EDNSOptionCode::COOKIE, makeEDNSCookiesOptString(cookiesOpt)) };
  addEntry("query with EDNS cookie of deadbeef", ednsOptions, "response to EDNS query with cookie of deadbeef");

  cookiesOpt.client = string("deadbeef");
  cookiesOpt.server = string("deadbeefdeadc0de");
  ednsOptions = { std::make_pair(EDNSOptionCode::COOKIE, makeEDNSCookiesOptString(cookiesOpt)) };
  /* should NOT collide with the previous one, since we hash cookies */
  addEntry("query with EDNS cookie of deadbeefdeadc0de", ednsOptions, "response to EDNS query with cookie of deadbeefdeadc0de");

  ednsOptions = { std::make_pair(EDNSOptionCode::PADDING, makeEDNSPaddingOptString(4)) };
  addEntry("query with EDNS padding of 4 bytes", ednsOptions, "response to EDNS query with padding of 4 bytes");

  ednsOptions = { std::make_pair(EDNSOptionCode::PADDING, makeEDNSPaddingOptString(5)) };
  /* should collide with the previous one since we skip padding */
  addEntry("query with EDNS padding of 5 bytes", ednsOptions, "response to EDNS query with padding of 5 bytes", true);

  cookiesOpt.client = string("deadbeef");
  cookiesOpt.server = string("deadbeef");
  ednsOptions = { std::make_pair(EDNSOptionCode::COOKIE, makeEDNSCookiesOptString(cookiesOpt)), std::make_pair(EDNSOptionCode::PADDING, makeEDNSPaddingOptString(4)) };
  addEntry("query with EDNS cookie of deadbeef plus padding of 4 bytes", ednsOptions, "response to EDNS query with a cookie of deadbeef and a padding of 4 bytes");

  cookiesOpt.client = string("deadbeef");
  cookiesOpt.server = string("deadbeefdeadc0de");
  ednsOptions = { std::make_pair(EDNSOptionCode::COOKIE, makeEDNSCookiesOptString(cookiesOpt)), std::make_pair(EDNSOptionCode::PADDING, makeEDNSPaddingOptString(5)) };
  /* should NOT match the previous since the content (and size!) of padding is ignored, but not the content (and size!) of cookies */
  addEntry("query with EDNS cookie of deadbeefdeadc0de plus padding of 5 bytes", ednsOptions, "response to EDNS query with a cookie of deadbeefdeadc0de and a padding of 5 bytes");

  checkEntryMatches("query without EDNS");
  checkEntryMatches("query with EDNS but no options");
  checkEntryMatches("query with ECS 192.0.2.1/32");
  checkEntryMatches("query with ECS 192.0.2.2/32");
  checkEntryMatches("query with EDNS cookie of deadbeef");
  checkEntryMatches("query with EDNS cookie of deadbeefdeadc0de");
  checkEntryMatches("query with EDNS padding of 4 bytes");
  checkEntryMatches("query with EDNS padding of 5 bytes", "query with EDNS padding of 4 bytes");
  checkEntryMatches("query with EDNS cookie of deadbeef plus padding of 4 bytes");
  checkEntryMatches("query with EDNS cookie of deadbeefdeadc0de plus padding of 5 bytes");
}

BOOST_AUTO_TEST_CASE(test_PCCollision) {
  const size_t maxEntries = 150000;
  DNSDistPacketCache PC(maxEntries, 86400, 1, 60, 3600, 60, false, 1, true, true);
  BOOST_CHECK_EQUAL(PC.getSize(), 0U);

  DNSName qname("www.powerdns.com.");
  uint16_t qtype = QType::AAAA;
  uint16_t qid = 0x42;
  uint32_t key;
  uint32_t secondKey;
  boost::optional<Netmask> subnetOut;
  bool dnssecOK = false;

  /* lookup for a query with a first ECS value,
     insert a corresponding response */
  {
    vector<uint8_t> query;
    DNSPacketWriter pwQ(query, qname, qtype, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = qid;
    DNSPacketWriter::optvect_t ednsOptions;
    EDNSSubnetOpts opt;
    opt.source = Netmask("10.0.20.1/32");
    ednsOptions.push_back(std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt)));
    pwQ.addOpt(512, 0, 0, ednsOptions);
    pwQ.commit();

    char responseBuf[4096];
    uint16_t responseBufSize = sizeof(responseBuf);
    ComboAddress remote("192.0.2.1");
    struct timespec queryTime;
    gettime(&queryTime);
    DNSQuestion dq(&qname, QType::AAAA, QClass::IN, 0, &remote, &remote, pwQ.getHeader(), query.size(), query.size(), false, &queryTime);
    bool found = PC.get(dq, qname.wirelength(), 0, responseBuf, &responseBufSize, &key, subnetOut, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_REQUIRE(subnetOut);
    BOOST_CHECK_EQUAL(subnetOut->toString(), opt.source.toString());

    vector<uint8_t> response;
    DNSPacketWriter pwR(response, qname, qtype, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->id = qid;
    pwR.startRecord(qname, qtype, 100, QClass::IN, DNSResourceRecord::ANSWER);
    ComboAddress v6("::1");
    pwR.xfrCAWithoutPort(6, v6);
    pwR.commit();
    pwR.addOpt(512, 0, 0, ednsOptions);
    pwR.commit();

    PC.insert(key, subnetOut, *(getFlagsFromDNSHeader(pwR.getHeader())), dnssecOK, qname, qtype, QClass::IN, reinterpret_cast<const char*>(response.data()), response.size(), false, RCode::NoError, boost::none);
    BOOST_CHECK_EQUAL(PC.getSize(), 1U);

    found = PC.get(dq, qname.wirelength(), 0, responseBuf, &responseBufSize, &key, subnetOut, dnssecOK);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_REQUIRE(subnetOut);
    BOOST_CHECK_EQUAL(subnetOut->toString(), opt.source.toString());
  }

  /* now lookup for the same query with a different ECS value,
     we should get the same key (collision) but no match */
  {
    vector<uint8_t> query;
    DNSPacketWriter pwQ(query, qname, qtype, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = qid;
    DNSPacketWriter::optvect_t ednsOptions;
    EDNSSubnetOpts opt;
    opt.source = Netmask("10.1.27.101/32");
    ednsOptions.push_back(std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt)));
    pwQ.addOpt(512, 0, 0, ednsOptions);
    pwQ.commit();

    char responseBuf[4096];
    uint16_t responseBufSize = sizeof(responseBuf);
    ComboAddress remote("192.0.2.1");
    struct timespec queryTime;
    gettime(&queryTime);
    DNSQuestion dq(&qname, QType::AAAA, QClass::IN, 0, &remote, &remote, pwQ.getHeader(), query.size(), query.size(), false, &queryTime);
    bool found = PC.get(dq, qname.wirelength(), 0, responseBuf, &responseBufSize, &secondKey, subnetOut, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK_EQUAL(secondKey, key);
    BOOST_REQUIRE(subnetOut);
    BOOST_CHECK_EQUAL(subnetOut->toString(), opt.source.toString());
    BOOST_CHECK_EQUAL(PC.getLookupCollisions(), 1U);
  }

#if 0
  /* to be able to compute a new collision if the packet cache hashing code is updated */
  {
    DNSDistPacketCache pc(10000);
    DNSPacketWriter::optvect_t ednsOptions;
    EDNSSubnetOpts opt;
    std::map<uint32_t, Netmask> colMap;
    size_t collisions = 0;
    size_t total = 0;
    //qname = DNSName("collision-with-ecs-parsing.cache.tests.powerdns.com.");

    for (size_t idxA = 0; idxA < 256; idxA++) {
      for (size_t idxB = 0; idxB < 256; idxB++) {
        for (size_t idxC = 0; idxC < 256; idxC++) {
          vector<uint8_t> secondQuery;
          DNSPacketWriter pwFQ(secondQuery, qname, QType::AAAA, QClass::IN, 0);
          pwFQ.getHeader()->rd = 1;
          pwFQ.getHeader()->qr = false;
          pwFQ.getHeader()->id = 0x42;
          opt.source = Netmask("10." + std::to_string(idxA) + "." + std::to_string(idxB) + "." + std::to_string(idxC) + "/32");
          ednsOptions.clear();
          ednsOptions.push_back(std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt)));
          pwFQ.addOpt(512, 0, 0, ednsOptions);
          pwFQ.commit();
          secondKey = pc.getKey(qname.toDNSString(), qname.wirelength(), secondQuery.data(), secondQuery.size(), false);
          auto pair = colMap.insert(std::make_pair(secondKey, opt.source));
          total++;
          if (!pair.second) {
            collisions++;
            cerr<<"Collision between "<<colMap[secondKey].toString()<<" and "<<opt.source.toString()<<" for key "<<secondKey<<endl;
            goto done;
          }
        }
      }
    }
  done:
    cerr<<"collisions: "<<collisions<<endl;
    cerr<<"total: "<<total<<endl;
  }
#endif
}

BOOST_AUTO_TEST_CASE(test_PCDNSSECCollision) {
  const size_t maxEntries = 150000;
  DNSDistPacketCache PC(maxEntries, 86400, 1, 60, 3600, 60, false, 1, true, true);
  BOOST_CHECK_EQUAL(PC.getSize(), 0U);

  DNSName qname("www.powerdns.com.");
  uint16_t qtype = QType::AAAA;
  uint16_t qid = 0x42;
  uint32_t key;
  boost::optional<Netmask> subnetOut;

  /* lookup for a query with DNSSEC OK,
     insert a corresponding response with DO set,
     check that it doesn't match without DO, but does with it */
  {
    vector<uint8_t> query;
    DNSPacketWriter pwQ(query, qname, qtype, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = qid;
    pwQ.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    pwQ.commit();

    char responseBuf[4096];
    uint16_t responseBufSize = sizeof(responseBuf);
    ComboAddress remote("192.0.2.1");
    struct timespec queryTime;
    gettime(&queryTime);
    DNSQuestion dq(&qname, QType::AAAA, QClass::IN, 0, &remote, &remote, pwQ.getHeader(), query.size(), query.size(), false, &queryTime);
    bool found = PC.get(dq, qname.wirelength(), 0, responseBuf, &responseBufSize, &key, subnetOut, true);
    BOOST_CHECK_EQUAL(found, false);

    vector<uint8_t> response;
    DNSPacketWriter pwR(response, qname, qtype, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->id = qid;
    pwR.startRecord(qname, qtype, 100, QClass::IN, DNSResourceRecord::ANSWER);
    ComboAddress v6("::1");
    pwR.xfrCAWithoutPort(6, v6);
    pwR.commit();
    pwR.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    pwR.commit();

    PC.insert(key, subnetOut, *(getFlagsFromDNSHeader(pwR.getHeader())), /* DNSSEC OK is set */ true, qname, qtype, QClass::IN, reinterpret_cast<const char*>(response.data()), response.size(), false, RCode::NoError, boost::none);
    BOOST_CHECK_EQUAL(PC.getSize(), 1U);

    found = PC.get(dq, qname.wirelength(), 0, responseBuf, &responseBufSize, &key, subnetOut, false);
    BOOST_CHECK_EQUAL(found, false);

    found = PC.get(dq, qname.wirelength(), 0, responseBuf, &responseBufSize, &key, subnetOut, true);
    BOOST_CHECK_EQUAL(found, true);
  }

}

BOOST_AUTO_TEST_SUITE_END()

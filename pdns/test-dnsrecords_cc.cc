#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>

#include <boost/tuple/tuple.hpp>
#include <boost/scoped_ptr.hpp>
#include "dnsrecords.hh"

namespace {
  enum class broken_marker {
    WORKING,
    BROKEN,
  };
}

// use a user-defined literal operator instead? should be supported in
// C++11, but only C++14 added the `s` suffix.
#define BINARY(s) (std::string(s, sizeof(s) - 1))

#define _CASE_L(type, inval, zoneval, lineval, broken) case_t(type, BINARY(inval), BINARY(zoneval), BINARY(lineval), broken)
#define CASE_L(type, inval, zoneval, lineval) _CASE_L(type, inval, zoneval, lineval, broken_marker::WORKING)
#define CASE_S(type, zoneval, lineval) _CASE_L(type, zoneval, zoneval, lineval, broken_marker::WORKING)
#define BROKEN_CASE_L(type, inval, zoneval, lineval) _CASE_L(type, inval, zoneval, lineval, broken_marker::BROKEN)
#define BROKEN_CASE_S(type, zoneval, lineval) _CASE_L(type, zoneval, zoneval, lineval, broken_marker::BROKEN)
BOOST_AUTO_TEST_SUITE(test_dnsrecords_cc)

#define REC_CHECK_EQUAL(a,b) { if (broken_marker::BROKEN == broken) { BOOST_WARN_EQUAL(a,b); } else {  BOOST_CHECK_EQUAL(a,b); } }
#define REC_CHECK_MESSAGE(cond,msg) { if (broken_marker::BROKEN == broken) { BOOST_WARN_MESSAGE(cond,msg); } else {  BOOST_CHECK_MESSAGE(cond,msg); } }
#define REC_FAIL_XSUCCESS(msg) { if (broken_marker::BROKEN == broken) { BOOST_CHECK_MESSAGE(false, std::string("Test has unexpectedly passed: ") + msg); } } // fail if test succeeds

BOOST_AUTO_TEST_CASE(test_record_types) {
  // tuple contains <type, user value, zone representation, line value, broken>
  typedef boost::tuple<QType::typeenum, std::string, std::string, std::string, broken_marker> case_t;
  typedef std::list<case_t> cases_t;
  reportAllTypes();
  MRRecordContent::report();
  IPSECKEYRecordContent::report();
  KXRecordContent::report();
  DHCIDRecordContent::report();
  TSIGRecordContent::report();
  TKEYRecordContent::report();

// NB!!! WHEN ADDING A TEST MAKE SURE YOU PUT IT NEXT TO ITS KIND
// TO MAKE SURE TEST NUMBERING DOES NOT BREAK

// why yes, they are unordered by name, how nice of you to notice

  const cases_t cases = boost::assign::list_of
// non-local name
     (BROKEN_CASE_L(QType::HINFO, "i686 \"Linux\"", "\"i686\" \"Linux\"", "\x04i686\x05Linux"))
     (BROKEN_CASE_L(QType::HINFO, "i686 Linux", "\"i686\" \"Linux\"", "\x04i686\x05Linux"))


/*   (CASE_S(QType::NAME, "zone format", "line format")) */
/*   (CASE_L(QType::NAME, "zone format", "canonic zone format", "line format")) */
;

  int n=0;
  int lq=-1;
  for(const cases_t::value_type& val :  cases) {
   const QType q(val.get<0>());
   const std::string& inval = val.get<1>();
   const std::string& zoneval = val.get<2>();
   const std::string& lineval = val.get<3>();
   const broken_marker broken = val.get<4>();

   if (lq != q.getCode()) n = 0;
   BOOST_CHECK_MESSAGE(q.getCode() >= lq, "record types not sorted correctly: " << q.getCode() << " < " << lq);
   lq = q.getCode();
   n++;
   BOOST_TEST_CHECKPOINT("Checking record type " << q.getName() << " test #" << n);
   BOOST_TEST_MESSAGE("Checking record type " << q.getName() << " test #" << n);
   try {
      std::string recData;
      auto rec = DNSRecordContent::mastermake(q.getCode(), 1, inval);
      BOOST_CHECK_MESSAGE(rec != NULL, "mastermake( " << q.getCode() << ", 1, " << inval << ") returned NULL");
      if (rec == NULL) continue;
      // now verify the record (note that this will be same as *zone* value (except for certain QTypes)

      switch(q.getCode()) {
      case QType::NS:
      case QType::PTR:
      case QType::MX:
      case QType::CNAME:
      case QType::SOA:
      case QType::TXT:
          // check *input* value instead
          REC_CHECK_EQUAL(rec->getZoneRepresentation(), inval);
          break;
      default:
          REC_CHECK_EQUAL(rec->getZoneRepresentation(), zoneval);
      }
      recData = rec->serialize(DNSName("rec.test"));

      std::shared_ptr<DNSRecordContent> rec2 = DNSRecordContent::unserialize(DNSName("rec.test"),q.getCode(),recData);
      BOOST_CHECK_MESSAGE(rec2 != NULL, "unserialize(rec.test, " << q.getCode() << ", recData) returned NULL");
      if (rec2 == NULL) continue;
      // now verify the zone representation (here it can be different!)
      REC_CHECK_EQUAL(rec2->getZoneRepresentation(), zoneval);
      // and last, check the wire format (using hex format for error readability)
      string cmpData = makeHexDump(lineval);
      recData = makeHexDump(recData);
      REC_CHECK_EQUAL(recData, cmpData);
   } catch (std::runtime_error &err) {
      REC_CHECK_MESSAGE(false, "Failed to verify " << q.getName() << ": " << err.what());
      continue;
   }
   REC_FAIL_XSUCCESS(q.getName() << " test #" << n << " has unexpectedly passed")
 }
}

bool test_dnsrecords_cc_predicate( std::exception const &ex ) { return true; }


BOOST_AUTO_TEST_SUITE_END()

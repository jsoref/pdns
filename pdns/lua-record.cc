#include "ext/luawrapper/include/LuaContext.hpp"
#include "lua-auth4.hh"
#include <thread>
#include "sstuff.hh"
#include <mutex>
#include "minicurl.hh"
#include "ueberbackend.hh"
#include <boost/format.hpp>

#include "../modules/geoipbackend/geoipbackend.hh" // only for the enum

/* to do:
   block AXFR unless TSIG, or override

   investigate IPv6

   check the wildcard 'no cache' stuff, we may get it wrong

   ponder ECS scopemask setting

   ponder netmask tree from file for huge number of netmasks

   unify ifupurl/ifupport
      add attribute for certificate check
   add list of current monitors
      expire them too?

   pool of UeberBackends?
 */

class IsUpOracle
{
private:
  typedef std::unordered_map<string,string> opts_t;
  struct CheckDesc
  {
    ComboAddress rem;
    string url;
    opts_t opts;
    bool operator<(const CheckDesc& rhs) const
    {
      std::map<string,string> oopts, rhsoopts;
      for(const auto& m : opts)
        oopts[m.first]=m.second;
      for(const auto& m : rhs.opts)
        rhsoopts[m.first]=m.second;
      
      return std::make_tuple(rem, url, oopts) <
        std::make_tuple(rhs.rem, rhs.url, rhsoopts);
    }
  };
public:
  bool isUp(const ComboAddress& remote, opts_t opts);
  bool isUp(const ComboAddress& remote, const std::string& url, opts_t opts=opts_t());
  bool isUp(const CheckDesc& cd);
    
private:
  void checkURLThread(ComboAddress rem, std::string url, opts_t opts);
  void checkTCPThread(ComboAddress rem, opts_t opts);

  struct Checker
  {
    std::thread* thr;
    bool status;
  };

  typedef map<CheckDesc, Checker> statuses_t;
  statuses_t d_statuses;
  
  std::mutex d_mutex;

  void setStatus(const CheckDesc& cd, bool status) 
  {
    std::lock_guard<std::mutex> l(d_mutex);
    d_statuses[cd].status=status;
  }

  void setDown(const ComboAddress& rem, const std::string& url=std::string(), opts_t opts=opts_t())
  {
    CheckDesc cd{rem, url, opts};
    setStatus(cd, false);
  }

  void setUp(const ComboAddress& rem, const std::string& url=std::string(), opts_t opts=opts_t())
  {
    CheckDesc cd{rem, url, opts};
    setStatus(cd, true);
  }

  void setDown(const CheckDesc& cd)
  {
    setStatus(cd, false);
  }

  void setUp(const CheckDesc& cd)
  {
    setStatus(cd, true);
  }

  bool upStatus(const ComboAddress& rem, const std::string& url=std::string(), opts_t opts=opts_t())
  {
    CheckDesc cd{rem, url, opts};
    std::lock_guard<std::mutex> l(d_mutex);
    return d_statuses[cd].status;
  }

  statuses_t getStatus()
  {
    std::lock_guard<std::mutex> l(d_mutex);
    return d_statuses;
  }

};

bool IsUpOracle::isUp(const CheckDesc& cd)
{
  std::lock_guard<std::mutex> l(d_mutex);
  auto iter = d_statuses.find(cd);
  if(iter == d_statuses.end()) {
//    L<<Logger::Warning<<"Launching TCP/IP status checker for "<<remote.toStringWithPort()<<endl;
    std::thread* checker = new std::thread(&IsUpOracle::checkTCPThread, this, cd.rem, cd.opts);
    d_statuses[cd]=Checker{checker, false};
    return false;
  }
  return iter->second.status;

}

bool IsUpOracle::isUp(const ComboAddress& remote, opts_t opts)
{
  CheckDesc cd{remote, "", opts};
  return isUp(cd);
}

bool IsUpOracle::isUp(const ComboAddress& remote, const std::string& url, std::unordered_map<string,string> opts)
{
  CheckDesc cd{remote, url, opts};
  std::lock_guard<std::mutex> l(d_mutex);
  auto iter = d_statuses.find(cd);
  if(iter == d_statuses.end()) {
    //    L<<Logger::Warning<<"Launching HTTP(s) status checker for "<<remote.toStringWithPort()<<" and URL "<<url<<endl;
    std::thread* checker = new std::thread(&IsUpOracle::checkURLThread, this, remote, url, opts);
    d_statuses[cd]=Checker{checker, false};
    return false;
  }
  
  return iter->second.status;
}

void IsUpOracle::checkTCPThread(ComboAddress rem, opts_t opts)
{
  CheckDesc cd{rem, "", opts};
  setDown(cd);
  for(bool first=true;;first=false) {
    try {
      Socket s(rem.sin4.sin_family, SOCK_STREAM);
      s.setNonBlocking();
      ComboAddress src;
      if(opts.count("source")) {
        src=ComboAddress(opts["source"]);
        s.bind(src);
      }
      s.connect(rem, 1);
      if(!isUp(cd)) {
        L<<Logger::Warning<<"Lua record monitoring declaring TCP/IP "<<rem.toStringWithPort()<<" ";
        if(opts.count("source"))
          L<<"(source "<<src.toString()<<") ";
        L<<"UP!"<<endl;
      }
      setUp(cd);
    }
    catch(NetworkError& ne) {
      if(isUp(rem, opts) || first)
        L<<Logger::Warning<<"Lua record monitoring declaring TCP/IP "<<rem.toStringWithPort()<<" DOWN: "<<ne.what()<<endl;
      setDown(cd);
    }
    sleep(1);
  }
}


void IsUpOracle::checkURLThread(ComboAddress rem, std::string url, opts_t opts) 
{
  setDown(rem, url, opts);
  for(bool first=true;;first=false) {
    try {
      MiniCurl mc;
      //      cout<<"Checking URL "<<url<<" at "<<rem.toString()<<endl;

      string content;
      if(opts.count("source")) {
        ComboAddress src(opts["source"]);
        content=mc.getURL(url, &rem, &src);
      }
      else
        content=mc.getURL(url, &rem);
      if(opts.count("stringmatch") && content.find(opts["stringmatch"]) == string::npos) {
        //        cout<<"URL "<<url<<" is up at "<<rem.toString()<<", but could not find stringmatch "<<opts["stringmatch"]<<" in page content, setting DOWN"<<endl;
        setDown(rem, url, opts);
        goto loop;
      }
      if(!upStatus(rem,url))
        L<<Logger::Warning<<"LUA record monitoring declaring "<<rem.toString()<<" UP for URL "<<url<<"!"<<endl;
      setUp(rem, url,opts);
    }
    catch(std::exception& ne) {
      if(upStatus(rem,url,opts) || first)
        L<<Logger::Warning<<"LUA record monitoring declaring "<<rem.toString()<<" DOWN for URL "<<url<<", error: "<<ne.what()<<endl;
      setDown(rem,url,opts);
    }
  loop:;
    sleep(5);
  }
}


IsUpOracle g_up;
namespace {
template<typename T, typename C>
bool doCompare(const T& var, const std::string& res, const C& cmp)
{
  if(auto country = boost::get<string>(&var)) 
    return cmp(*country, res);

  auto countries=boost::get<vector<pair<int,string> > >(&var);
  for(const auto& country : *countries) {
    if(cmp(country.second, res))
      return true;
  }
  return false;
}
}


std::string getGeo(const std::string& ip, GeoIPBackend::GeoIPQueryAttribute qa)
{
  static bool initialized;
  extern std::function<std::string(const std::string& ip, int)> g_getGeo;
  if(!g_getGeo) {
    if(!initialized) {
      L<<Logger::Error<<"LUA Record attempted to use GeoIPBackend functionality, but backend not launched"<<endl;
      initialized=true;
    }
    return "unknown";
  }
  else
    return g_getGeo(ip, (int)qa);
}

static ComboAddress pickrandom(vector<ComboAddress>& ips)
{
  return ips[random() % ips.size()];
}

static ComboAddress hashed(const ComboAddress& who, vector<ComboAddress>& ips)
{
  ComboAddress::addressOnlyHash aoh;
  return ips[aoh(who) % ips.size()];
}


static ComboAddress wrandom(vector<pair<int,ComboAddress> >& wips)
{
  int sum=0;
  vector<pair<int, ComboAddress> > pick;
  for(auto& i : wips) {
    sum += i.first;
    pick.push_back({sum, i.second});
  }
  int r = random() % sum;
  auto p = upper_bound(pick.begin(), pick.end(),r, [](int r, const decltype(pick)::value_type& a) { return  r < a.first;});
  return p->second;
}

static ComboAddress whashed(const ComboAddress& bestwho, vector<pair<int,ComboAddress> >& wips)
{
  int sum=0;
  vector<pair<int, ComboAddress> > pick;
  for(auto& i : wips) {
    sum += i.first;
    pick.push_back({sum, i.second});
  }
  ComboAddress::addressOnlyHash aoh;
  int r = aoh(bestwho) % sum;
  auto p = upper_bound(pick.begin(), pick.end(),r, [](int r, const decltype(pick)::value_type& a) { return  r < a.first;});
  return p->second;
}

static bool getLatLon(const std::string& ip, double& lat, double& lon)
{
  string inp = getGeo(ip, GeoIPBackend::LatLon);
  if(inp.empty())
    return false;
  lat=atof(inp.c_str());
  auto pos=inp.find(' ');
  if(pos != string::npos)
    lon=atof(inp.c_str() + pos);
  return true;
}

static bool getLatLon(const std::string& ip, string& loc)
{
  int latdeg, latmin, londeg, lonmin;
  double latsec, lonsec;
  char lathem='X', lonhem='X';
  
  double lat, lon;
  if(!getLatLon(ip, lat, lon))
    return false;

  if(lat > 0) {
    lathem='N';
  }
  else {
    lat = -lat;
    lathem='S';
  }

  if(lon > 0) {
    lonhem='E';
  }
  else {
    lon = -lon;
    lonhem='W';
  }

  /*
    >>> deg = int(R)
    >>> min = int((R - int(R)) * 60.0)
    >>> sec = (((R - int(R)) * 60.0) - min) * 60.0
    >>> print("{}º {}' {}\"".format(deg, min, sec))
  */

  
  latdeg = lat;
  latmin = (lat - latdeg)*60.0;
  latsec = (((lat - latdeg)*60.0) - latmin)*60.0;

  londeg = lon;
  lonmin = (lon - londeg)*60.0;
  lonsec = (((lon - londeg)*60.0) - lonmin)*60.0;

  // 51 59 00.000 N 5 55 00.000 E 4.00m 1.00m 10000.00m 10.00m

  boost::format fmt("%d %d %d %c %d %d %d %c 0.00m 1.00m 10000.00m 10.00m");

  loc= (fmt % latdeg % latmin % latsec % lathem % londeg % lonmin % lonsec % lonhem ).str();
  return true;
}
                      
                      

static ComboAddress closest(const ComboAddress& bestwho, vector<ComboAddress>& wips)
{
  map<double,vector<ComboAddress> > ranked;
  double wlat=0, wlon=0;
  getLatLon(bestwho.toString(), wlat, wlon);
  //        cout<<"bestwho "<<wlat<<", "<<wlon<<endl;
  vector<string> ret;
  for(const auto& c : wips) {
    double lat=0, lon=0;
    getLatLon(c.toString(), lat, lon);
    //          cout<<c.toString()<<": "<<lat<<", "<<lon<<endl;
    double latdiff = wlat-lat;
    double londiff = wlon-lon;
    if(londiff > 180)
      londiff = 360 - londiff; 
    double dist2=latdiff*latdiff + londiff*londiff;
    //          cout<<"    distance: "<<sqrt(dist2) * 40000.0/360<<" km"<<endl; // length of a degree
    ranked[dist2].push_back(c);
  }
  return ranked.begin()->second[random() % ranked.begin()->second.size()];
}

static std::vector<DNSZoneRecord> lookup(const DNSName& name, uint16_t qtype, int zoneid)
{
  static UeberBackend ub;
  static std::mutex mut;
  std::lock_guard<std::mutex> lock(mut);
  ub.lookup(QType(qtype), name, nullptr, zoneid);
  DNSZoneRecord dr;
  vector<DNSZoneRecord> ret;
  while(ub.get(dr)) {
    ret.push_back(dr);
  }
  return ret;
}

std::vector<shared_ptr<DNSRecordContent>> luaSynth(const std::string& code, const DNSName& query, const DNSName& zone, int zoneid, const DNSPacket& dnsp, uint16_t qtype) 
{
  //  cerr<<"Called for "<<query<<", in zone "<<zone<<" for type "<<qtype<<endl;
  //  cerr<<"Code: '"<<code<<"'"<<endl;
  
  AuthLua4 alua("");
  std::vector<shared_ptr<DNSRecordContent>> ret;
  
  LuaContext& lua = *alua.getLua();
  lua.writeVariable("qname", query);
  lua.writeVariable("who", dnsp.getRemote());
  ComboAddress bestwho;
  if(dnsp.hasEDNSSubnet()) {
    lua.writeVariable("ecswho", dnsp.getRealRemote());
    bestwho=dnsp.getRealRemote().getNetwork();
    lua.writeVariable("bestwho", dnsp.getRealRemote().getNetwork());
  }
  else {
    bestwho=dnsp.getRemote();
  }

  lua.writeFunction("latlon", [&bestwho]() {
      double lat, lon;
      getLatLon(bestwho.toString(), lat, lon);
      return std::to_string(lat)+" "+std::to_string(lon);
    });

  lua.writeFunction("latlonloc", [&bestwho]() {
      string loc;
      getLatLon(bestwho.toString(), loc);
      cout<<"loc: "<<loc<<endl;
      return loc;
  });

   
  lua.writeFunction("closestMagic", [&bestwho,&query](){
      vector<ComboAddress> candidates;
      for(auto l : query.getRawLabels()) {
        boost::replace_all(l, "-", ".");
        try {
          candidates.emplace_back(l);
        }
        catch(...) {
          break;
        }
      }
      
      return closest(bestwho, candidates).toString();
    });
  

  
  lua.writeFunction("createReverse", [&bestwho,&query,&zone](string suffix, boost::optional<std::unordered_map<string,string>> e){
      try {
      auto labels= query.getRawLabels();
      if(labels.size()<4)
        return std::string("unknown");

      vector<ComboAddress> candidates;

      // exceptions are relative to zone
      // so, query comes in for 4.3.2.1.in-addr.arpa, zone is called 2.1.in-addr.arpa
      // e["1.2.3.4"]="bert.powerdns.com" - should match, easy enough to do
      // the issue is with classless delegation.. 
      if(e) {
        ComboAddress req(labels[3]+"."+labels[2]+"."+labels[1]+"."+labels[0], 0);
        const auto& uom = *e;
        for(const auto& c : uom)
          if(ComboAddress(c.first, 0) == req)
            return c.second;
      }
      

      boost::format fmt(suffix);
      fmt.exceptions( boost::io::all_error_bits ^ ( boost::io::too_many_args_bit | boost::io::too_few_args_bit )  );
      fmt % labels[3] % labels[2] % labels[1] % labels[0];

      fmt % (labels[3]+"-"+labels[2]+"-"+labels[1]+"-"+labels[0]);

      boost::format fmt2("%02x%02x%02x%02x");
      for(int i=3; i>=0; --i)
        fmt2 % atoi(labels[i].c_str());

      fmt % (fmt2.str());

      return fmt.str();
      }
      catch(std::exception& e) {
        cerr<<"error: "<<e.what()<<endl;
      }
      return std::string("error");
    });

  lua.writeFunction("createForward", [&zone, &query]() {
      DNSName rel=query.makeRelative(zone);
      auto parts = rel.getRawLabels();
      if(parts.size()==4)
        return parts[0]+"."+parts[1]+"."+parts[2]+"."+parts[3];
      if(parts.size()==1) {
        // either hex string, or 12-13-14-15
        cout<<parts[0]<<endl;
        int x1, x2, x3, x4;
        if(sscanf(parts[0].c_str()+2, "%02x%02x%02x%02x", &x1, &x2, &x3, &x4)==4) {
          return std::to_string(x1)+"."+std::to_string(x2)+"."+std::to_string(x3)+"."+std::to_string(x4);
        }
          
        
      }
      return std::string("0.0.0.0");
    });

  lua.writeFunction("createForward6", [&query,&zone]() {
      DNSName rel=query.makeRelative(zone);
      auto parts = rel.getRawLabels();
      if(parts.size()==8) {
        string tot;
        for(int i=0; i<8; ++i) {
          if(i)
            tot.append(1,':');
          tot+=parts[i];
        }
        ComboAddress ca(tot);
        return ca.toString();
      }
      else if(parts.size()==1) {
        boost::replace_all(parts[0],"-",":");
        ComboAddress ca(parts[0]);
        return ca.toString();
      }

      return std::string("::");
    });

  
  lua.writeFunction("createReverse6", [&bestwho,&query,&zone](string suffix, boost::optional<std::unordered_map<string,string>> e){
      vector<ComboAddress> candidates;

      try {
        auto labels= query.getRawLabels();
        if(labels.size()<32)
          return std::string("unknown");
        cout<<"Suffix: '"<<suffix<<"'"<<endl;
        boost::format fmt(suffix);
        fmt.exceptions( boost::io::all_error_bits ^ ( boost::io::too_many_args_bit | boost::io::too_few_args_bit )  );
    

        string together;
        vector<string> quads;
        for(int i=0; i<8; ++i) {
          if(i)
            together+=":";
          string quad;
          for(int j=0; j <4; ++j) {
            quad.append(1, labels[31-i*4-j][0]);
            together += labels[31-i*4-j][0];
          }
          quads.push_back(quad);
        }
        ComboAddress ip6(together,0);

        if(e) {
          auto& addrs=*e;
          for(const auto& addr: addrs) {
            // this makes sure we catch all forms of the address
            if(ComboAddress(addr.first,0)==ip6)
              return addr.second;
          }
        }
        
        string dashed=ip6.toString();
        boost::replace_all(dashed, ":", "-");
        
        for(int i=31; i>=0; --i)
          fmt % labels[i];
        fmt % dashed;

        for(const auto& quad : quads)
          fmt % quad;
        
        return fmt.str();
      }
      catch(std::exception& e) {
        cerr<<"Exception: "<<e.what()<<endl;
      }
      catch(PDNSException& e) {
        cerr<<"Exception: "<<e.reason<<endl;
      }
      return std::string("unknown");
    });

  
  lua.writeFunction("ifportup", [&bestwho](int port, const vector<pair<int, string> >& ips, const boost::optional<std::unordered_map<string,string>> options) {
      vector<ComboAddress> candidates;
      std::unordered_map<string, string> opts;
      if(options)
        opts = *options;
      
      for(const auto& i : ips) {
        ComboAddress rem(i.second, port);
        if(g_up.isUp(rem, opts))
          candidates.push_back(rem);
      }
      vector<string> ret;
      if(candidates.empty()) {
        //        cout<<"Everything is down. Returning all of them"<<endl;
        for(const auto& i : ips) 
          ret.push_back(i.second);
      }
      else {
        ComboAddress res;
        string selector="random";
        if(options) {
          if(options->count("selector"))
            selector=options->find("selector")->second;
        }
        if(selector=="random")
          res=pickrandom(candidates);
        else if(selector=="closest")
          res=closest(bestwho, candidates);
        else if(selector=="hashed")
          res=hashed(bestwho, candidates);
        else {
          L<<Logger::Warning<<"LUA Record ifportup called with unknown selector '"<<selector<<"'"<<endl;
          res=pickrandom(candidates);
        }
        ret.push_back(res.toString());
      }
      return ret;
    });


  lua.writeFunction("ifurlup", [](const std::string& url,
                                  const boost::variant<
                                  vector<pair<int, string> >,
                                  vector<pair<int, vector<pair<int, string> > > >
                                  > & ips, boost::optional<std::unordered_map<string,string>> options) {

      vector<vector<ComboAddress> > candidates;
      std::unordered_map<string,string> opts;
      if(options)
        opts = *options;
      if(auto simple = boost::get<vector<pair<int,string>>>(&ips)) {
        vector<ComboAddress> unit;
        for(const auto& i : *simple) {
          ComboAddress rem(i.second, 80);
          unit.push_back(rem);
        }
        candidates.push_back(unit);
      } else {
        auto units = boost::get<vector<pair<int, vector<pair<int, string> > > >>(ips);
        for(const auto& u : units) {
          vector<ComboAddress> unit;
          for(const auto& c : u.second) {
            ComboAddress rem(c.second, 80);
            unit.push_back(rem);
          }
          candidates.push_back(unit);
        }
      }

      //
      //      cout<<"Have "<<candidates.size()<<" units of IP addresses: "<<endl;
      vector<string> ret;
      for(const auto& unit : candidates) {
        vector<ComboAddress> available;
        for(const auto& c : unit)
          if(g_up.isUp(c, url, opts))
            available.push_back(c);
        if(available.empty()) {
          //  cerr<<"Entire unit is down, trying next one if available"<<endl;
          continue;
        }
        ret.push_back(available[random() % available.size()].toString());
        return ret;
      }      
      //      cerr<<"ALL units are down, returning all IP addresses"<<endl;
      for(const auto& unit : candidates) {
        for(const auto& c : unit)
          ret.push_back(c.toString());
      }

      return ret;
                    });



  /* idea: we have policies on vectors of ComboAddresses, like
     random, wrandom, whashed, closest. In C++ this is ComboAddress in,
     ComboAddress out. In Lua, vector string in, string out */
  
  lua.writeFunction("pickrandom", [](const vector<pair<int, string> >& ips) {
      return ips[random()%ips.size()].second;
    });

  // wrandom({ {100, '1.2.3.4'}, {50, '5.4.3.2'}, {1, '192.168.1.0'}})"

  lua.writeFunction("wrandom", [](std::unordered_map<int, std::unordered_map<int, string> > ips) {
      vector<pair<int,ComboAddress> > conv;
      for(auto& i : ips) 
        conv.emplace_back(atoi(i.second[1].c_str()), ComboAddress(i.second[2]));
      
      return wrandom(conv).toString();
    });

  lua.writeFunction("whashed", [&bestwho](std::unordered_map<int, std::unordered_map<int, string> > ips) {
      vector<pair<int,ComboAddress> > conv;
      for(auto& i : ips) 
        conv.emplace_back(atoi(i.second[1].c_str()), ComboAddress(i.second[2]));
      
      return whashed(bestwho, conv).toString();
      
    });


  lua.writeFunction("closest", [&bestwho](std::unordered_map<int, std::unordered_map<int, string> > ips) {
      vector<ComboAddress > conv;
      for(auto& i : ips) 
        conv.emplace_back(i.second[2]);
      
      return closest(bestwho, conv).toString();
      
    });

  
  int counter=0;
  lua.writeFunction("report", [&counter](string event, boost::optional<string> line){
      throw std::runtime_error("Script took too long");
    });
  lua.executeCode("debug.sethook(report, '', 1000)");

  
  typedef const boost::variant<string,vector<pair<int,string> > > combovar_t;
  lua.writeFunction("continent", [&bestwho](const combovar_t& continent) {
      string res=getGeo(bestwho.toString(), GeoIPBackend::Continent);
      return doCompare(continent, res, [](const std::string& a, const std::string& b) {
          return !strcasecmp(a.c_str(), b.c_str());
        });
    });

  lua.writeFunction("asnum", [&bestwho](const combovar_t& asns) {
      string res=getGeo(bestwho.toString(), GeoIPBackend::ASn);
      return doCompare(asns, res, [](const std::string& a, const std::string& b) {
          return !strcasecmp(a.c_str(), b.c_str());
        });
    });
  
  lua.writeFunction("country", [&bestwho](const combovar_t& var) {
      string res = getGeo(bestwho.toString(), GeoIPBackend::Country2);
      return doCompare(var, res, [](const std::string& a, const std::string& b) {
          return !strcasecmp(a.c_str(), b.c_str());
        });
       
    });

  lua.writeFunction("netmask", [bestwho](const vector<pair<int,string>>& ips) {
      for(const auto& i :ips) {
        Netmask nm(i.second);
        if(nm.match(bestwho))
          return true;
      }
      return false;
    });

  /* {
       {
        {'192.168.0.0/16', '10.0.0.0/8'}, 
        {'192.168.20.20', '192.168.20.21'}
       },
       {
        {'0.0.0.0/0'}, {'192.0.2.1'}
       }
     }
  */  
  lua.writeFunction("view", [bestwho](const vector<pair<int, vector<pair<int, vector<pair<int, string> > > > > >& in) {
      for(const auto& rule : in) {
        const auto& netmasks=rule.second[0].second;
        const auto& destinations=rule.second[1].second;
        for(const auto& nmpair : netmasks) {
          Netmask nm(nmpair.second);
          if(nm.match(bestwho)) {
            return destinations[random() % destinations.size()].second;
          }
        }
      }
      return std::string();
    }
    );
  
  
  lua.writeFunction("include", [&lua,zone,zoneid](string record) {
      try {
        cout<<"include("<<record<<")"<<endl;
        vector<DNSZoneRecord> drs = lookup(DNSName(record) +zone, QType::LUA, zoneid);
        for(const auto& dr : drs) {
          auto lr = getRR<LUARecordContent>(dr.dr);
          lua.executeCode(lr->getCode());
        }
      }
      catch(std::exception& e) {
        L<<Logger::Error<<"Failed to load include record for LUArecord "<<(DNSName(record)+zone)<<": "<<e.what()<<endl;
      }
    });

  
  try {
    string actual;
    if(!code.empty() && code[0]!=';')
      actual = "return ";
    actual+=code;

    auto content=lua.executeCode<boost::variant<string, vector<pair<int, string> > > >(actual);

    vector<string> contents;
    if(auto str = boost::get<string>(&content))
      contents.push_back(*str);
    else
      for(const auto& c : boost::get<vector<pair<int,string>>>(content))
        contents.push_back(c.second);
    
    for(const auto& content: contents) {
      if(qtype==QType::TXT)
        ret.push_back(std::shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(qtype, 1, '"'+content+'"' )));
      else
        ret.push_back(std::shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(qtype, 1, content )));
    }
  }catch(std::exception &e) {
    cerr<<"Lua reported: "<<e.what()<<endl;
  }

  return ret;
}

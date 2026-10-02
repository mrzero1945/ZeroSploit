// Host-only tests for the JSON builder in zs_util.cpp.
//
// This lives apart from test_packets.cpp because zs_helper.cpp and zs_util.cpp
// both define helpers (trim/split/J) and including both in one translation
// unit collides.
#include "zs_util.cpp"

#include <algorithm>
#include <cstdio>
#include <string>

static int fails = 0;

static void ok(const char* what, bool cond) {
  printf("%-42s %s\n", what, cond ? "PASS" : "FAIL");
  if (!cond) fails++;
}

static bool balanced(const std::string& s) {
  return std::count(s.begin(), s.end(), '{') == std::count(s.begin(), s.end(), '}');
}

int main() {
  // ---- basics ----------------------------------------------------------
  {
    zs::Json j;
    j.obj().key("count").val(2).end();
    ok("basic object", j.str().find("\"count\": 2") != std::string::npos);
    ok("basic object ends with }", j.str().back() == '}');
    ok("basic object balanced", balanced(j.str()));
  }

  // ---- the shape opNetworkInfo produces ---------------------------------
  {
    zs::Json arr;
    arr.obj().key("count").val(1);
    std::string items = "[{\"name\":\"wlan0\"}]";
    arr.key("ifaces").raw(items);

    zs::Json rj;
    rj.obj().key("available").val(true).key("granted").val(true).end();
    arr.key("root").raw(rj.str());
    arr.end();

    std::string s = arr.str();
    ok("nested keeps every key",
       s.find("\"count\"") != std::string::npos &&
       s.find("\"ifaces\"") != std::string::npos &&
       s.find("\"root\"") != std::string::npos);
    ok("nested balanced", balanced(s));
    ok("nested ends with }", s.back() == '}');
    ok("no trailing garbage after close", s.find("}\n\"root\"") == std::string::npos);
  }

  // ---- regression: end() called more times than obj() ------------------
  // depth_ used to go negative, the negative indent length made
  // std::string::append throw std::length_error, and the -fno-exceptions build
  // turned that into a SIGABRT on the first screen.
  {
    zs::Json over;
    over.obj().key("x").val(1).end().end().end();
    ok("extra end() survives", over.str().size() > 0);
    ok("extra end() still closes", over.str().back() == '}');
  }

  // ---- deep nesting ---------------------------------------------------
  {
    zs::Json deep;
    deep.obj();
    for (int i = 0; i < 6; i++) deep.obj();
    for (int i = 0; i < 7; i++) deep.end();
    ok("deep nesting balanced", balanced(deep.str()));
  }

  // ---- regression: string literal must not bind to val(bool) -----------
  {
    zs::Json j;
    j.obj().key("state").val("open").end();
    std::string s = j.str();
    ok("string literal is a string", s.find("\"state\": \"open\"") != std::string::npos);
    ok("string literal is not true", s.find("true") == std::string::npos);

    zs::Json k;
    k.obj().key("a").val("x").key("b").val(1).end();
    ok("literal and int side by side",
       k.str().find("\"a\": \"x\"") != std::string::npos &&
       k.str().find("\"b\": 1") != std::string::npos);
  }

  // ---- escaping / types -----------------------------------------------
  {
    zs::Json j;
    j.obj().key("quote\"key").val("line\nbreak").end();
    // key is quote"key -> emitted as quote\"key
    ok("escapes quote in key", j.str().find("quote\\\"key") != std::string::npos);
    ok("escapes newline in value", j.str().find("\\n") != std::string::npos);
  }
  {
    zs::Json j;
    j.obj().key("i").val(7).key("d").val(1.5).key("b").val(true).end();
    ok("int renders as number", j.str().find("\"i\": 7") != std::string::npos);
    ok("double renders", j.str().find("\"d\": 1.5") != std::string::npos);
    ok("bool renders", j.str().find("\"b\": true") != std::string::npos);
  }

  printf("\n%s (%d failure(s))\n", fails ? "FAILED" : "ALL PASS", fails);
  return fails ? 1 : 0;
}

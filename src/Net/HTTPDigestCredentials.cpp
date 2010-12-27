

#include "Poco/DateTime.h"
#include "Poco/DateTimeFormat.h"
#include "Poco/DateTimeFormatter.h"
#include "Poco/Exception.h"
#include "Poco/MD5Engine.h"
#include "Poco/Net/HTTPAuthenticationParams.h"
#include "Poco/Net/HTTPDigestCredentials.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/NumberFormatter.h"


namespace Poco {
namespace Net {
namespace {


std::string clientNonce()
{
    MD5Engine engine;

    engine.update(DateTimeFormatter::format(Timestamp(), DateTimeFormat::ISO8601_FORMAT));

    return DigestEngine::digestToHex(engine.digest());
}


std::string quoted(const std::string& s)
{
    return '"' + s + '"';
}


int increaseCounter(std::map<std::string, int>& map, const std::string& nonce)
{
    std::map<std::string, int>::iterator it = map.find(nonce);

    if (it == map.end()) {
        it = map.insert(std::map<std::string, int>::value_type(nonce, 0)).first;
    }

    it->second += 1;

    return it->second;
}


std::string digest(DigestEngine& engine,
                   const std::string& a,
                   const std::string& b)
{
    engine.reset();
    engine.update(a);
    engine.update(':');
    engine.update(b);

    return DigestEngine::digestToHex(engine.digest());
}


std::string digest(DigestEngine& engine,
                   const std::string& a,
                   const std::string& b,
                   const std::string& c)
{
    engine.reset();
    engine.update(a);
    engine.update(':');
    engine.update(b);
    engine.update(':');
    engine.update(c);

    return DigestEngine::digestToHex(engine.digest());
}


std::string digest(DigestEngine& engine,
                   const std::string& a,
                   const std::string& b,
                   const std::string& c,
                   const std::string& d,
                   const std::string& e,
                   const std::string& f)
{
    engine.reset();
    engine.update(a);
    engine.update(':');
    engine.update(b);
    engine.update(':');
    engine.update(c);
    engine.update(':');
    engine.update(d);
    engine.update(':');
    engine.update(e);
    engine.update(':');
    engine.update(f);

    return DigestEngine::digestToHex(engine.digest());
}


}// namespace


const std::string HTTPDigestCredentials::SCHEME = "Digest";


HTTPDigestCredentials::HTTPDigestCredentials():
    _cnonce(clientNonce())
{
}

	
HTTPDigestCredentials::HTTPDigestCredentials(const std::string& username, const std::string& password):
    _username(username),
    _password(password),
    _cnonce(clientNonce())
{
}


void HTTPDigestCredentials::setUsername(const std::string& username)
{
    _username = username;
}
	

void HTTPDigestCredentials::setPassword(const std::string& password)
{
    _password = password;
}


void HTTPDigestCredentials::authenticate(HTTPRequest& request, const HTTPResponse& response)
{
    HTTPAuthenticationParams responseAuthParams(response);

    if (!responseAuthParams.has("nonce") ||
        !responseAuthParams.has("realm"))
    {
        throw InvalidArgumentException("Invalid HTTP response");
    }

    const std::string& algorithm = responseAuthParams.get("algorithm", "MD5");

    if (icompare(algorithm, "MD5") != 0) {
        throw NotImplementedException("Unsupported digest algorithm", algorithm);
    }

    const std::string& nonce = responseAuthParams.get("nonce");
    const std::string& opaque = responseAuthParams.get("opaque", "");
    const std::string& qop = responseAuthParams.get("qop", "");
    const std::string& realm = responseAuthParams.getRealm();

    HTTPAuthenticationParams requestAuthParams;

    requestAuthParams.set("username", quoted(_username));
    requestAuthParams.set("uri", request.getURI());
    requestAuthParams.set("nonce", nonce);
    requestAuthParams.setRealm(quoted(realm));
    if (!opaque.empty()) {
        requestAuthParams.set("opaque", opaque);
    }

    MD5Engine engine;

    std::string ha1 = digest(engine, _username, realm, _password);
    std::string ha2 = digest(engine, request.getMethod(), request.getURI());

    // if (icompare(algorithm, "MD5-sess") == 0) {
    //     ha1 = digest(engine, ha1, nonce, _cnonce);
    // }

    if (!qop.empty()) {
        if (icompare(qop, "auth") == 0) {
            const std::string nc = Poco::NumberFormatter::formatHex(increaseCounter(_nc, nonce), 8);

            requestAuthParams.set("nc", nc);
            requestAuthParams.set("cnonce", _cnonce);
            requestAuthParams.set("qop", qop);
            requestAuthParams.set("response", digest(engine, ha1, nonce, nc, _cnonce, qop, ha2));
        } else {
            throw NotImplementedException("Unsupported quality of protection", responseAuthParams.get("qop"));
        }
    } else {
        requestAuthParams.set("response", digest(engine, ha1, nonce, ha2));
    }

    request.setCredentials(SCHEME, requestAuthParams.toString());
}


} } // namespace Poco::Net

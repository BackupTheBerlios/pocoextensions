

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


std::string quoted(const std::string& s)
{
    std::string result;

    result.reserve(1 + s.size() + 1);
    result += '"';
    result += s;
    result += '"';

    return result;
}


std::string digest(DigestEngine& engine,
                   const std::string& a,
                   const std::string& b,
                   const std::string& c = std::string(),
                   const std::string& d = std::string(),
                   const std::string& e = std::string(),
                   const std::string& f = std::string())
{
    engine.reset();
    engine.update(a);
    engine.update(':');
    engine.update(b);
    if (!c.empty()) {
        engine.update(':');
        engine.update(c);
        if (!d.empty()) {
            engine.update(':');
            engine.update(d);
            engine.update(':');
            engine.update(e);
            engine.update(':');
            engine.update(f);
        }
    }

    return DigestEngine::digestToHex(engine.digest());
}


}// namespace


const std::string HTTPDigestCredentials::SCHEME = "Digest";


HTTPDigestCredentials::HTTPDigestCredentials():
    _cnonce(createNonce())
{
}

	
HTTPDigestCredentials::HTTPDigestCredentials(const std::string& username, const std::string& password):
    _username(username),
    _password(password),
    _cnonce(createNonce())
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
    authenticate(request, HTTPAuthenticationParams(response));
}


void HTTPDigestCredentials::authenticate(HTTPRequest& request, const HTTPAuthenticationParams& responseAuthParams)
{
    if (!responseAuthParams.has("nonce") ||
        !responseAuthParams.has("realm"))
    {
        throw InvalidArgumentException("Invalid HTTP authentication parameters");
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

    const std::string ha1 = digest(engine, _username, realm, _password);
    const std::string ha2 = digest(engine, request.getMethod(), request.getURI());

    // if (icompare(algorithm, "MD5-sess") == 0) {
    //     ha1 = digest(engine, ha1, nonce, _cnonce);
    // }

    if (qop.empty()) {
        requestAuthParams.set("response", digest(engine, ha1, nonce, ha2));
    } else if (icompare(qop, "auth") == 0) {
        const std::string nc = NumberFormatter::formatHex(updateNonceCounter(nonce), 8);

        requestAuthParams.set("nc", nc);
        requestAuthParams.set("cnonce", _cnonce);
        requestAuthParams.set("qop", qop);
        requestAuthParams.set("response", digest(engine, ha1, nonce, nc, _cnonce, qop, ha2));
    } else if (icompare(qop, "auth-int") == 0) {
        // TODO
        throw NotImplementedException("Integrity protection is not implemented");
    } else {
        throw InvalidArgumentException("Invalid quality of protection", qop);
    }

    request.setCredentials(SCHEME, requestAuthParams.toString());
}


std::string HTTPDigestCredentials::createNonce()
{
    static unsigned int counter = 0;

    MD5Engine md5;
    Timestamp::TimeVal now = Timestamp().epochMicroseconds();

    md5.update(&counter, sizeof(counter));
    md5.update(&now, sizeof(now));

    ++counter;

    return DigestEngine::digestToHex(md5.digest());
}


int HTTPDigestCredentials::updateNonceCounter(const std::string& nonce)
{
    NonceCounterMap::iterator iter = _nc.find(nonce);

    if (iter == _nc.end()) {
        iter = _nc.insert(NonceCounterMap::value_type(nonce, 0)).first;
    }

    iter->second += 1;

    return iter->second;
}


} } // namespace Poco::Net

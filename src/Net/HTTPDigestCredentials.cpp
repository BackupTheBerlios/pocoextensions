//
// HTTPDigestCredentials.cpp
//
// Copyright (c) 2011 Anton V. Yabchinskiy (arn at users dot berlios dot de)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//


#include "Poco/DateTime.h"
#include "Poco/DateTimeFormat.h"
#include "Poco/DateTimeFormatter.h"
#include "Poco/Exception.h"
#include "Poco/MD5Engine.h"
#include "Poco/Net/HTTPDigestCredentials.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/NumberFormatter.h"


namespace Poco {
namespace Net {
namespace {


const std::string defaultAlgorithm = "MD5";
const std::string defaultQop       = "";


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


std::string formatNonceCounter(int counter)
{
    return NumberFormatter::formatHex(counter, 8);
}


}// namespace


const std::string HTTPDigestCredentials::SCHEME = "Digest";


HTTPDigestCredentials::HTTPDigestCredentials():
    _username(),
    _password(),
    _requestAuthParams(),
    _nc()
{
}


HTTPDigestCredentials::HTTPDigestCredentials(const std::string& username, const std::string& password):
    _username(username),
    _password(password),
    _requestAuthParams(),
    _nc()
{
}


HTTPDigestCredentials::~HTTPDigestCredentials()
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
    createAuthParams(request, responseAuthParams);
    request.setCredentials(SCHEME, _requestAuthParams.toString());
}


void HTTPDigestCredentials::updateAuthInfo(HTTPRequest& request)
{
    updateAuthParams(request);
    request.setCredentials(SCHEME, _requestAuthParams.toString());
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


void HTTPDigestCredentials::createAuthParams(const HTTPRequest& request,
                                             const HTTPAuthenticationParams& responseAuthParams)
{
    // TODO: “domain” auth parameter.
    // TODO: Integrity protection.

    if (!responseAuthParams.has("nonce") ||
        !responseAuthParams.has("realm"))
    {
        throw InvalidArgumentException("Invalid HTTP authentication parameters");
    }

    const std::string& algorithm = responseAuthParams.get("algorithm", defaultAlgorithm);

    if (icompare(algorithm, "MD5") != 0) {
        throw NotImplementedException("Unsupported digest algorithm", algorithm);
    }

    const std::string& nonce = responseAuthParams.get("nonce");
    const std::string& qop = responseAuthParams.get("qop", defaultQop);
    const std::string& realm = responseAuthParams.getRealm();

    _requestAuthParams.clear();
    _requestAuthParams.set("username", _username);
    _requestAuthParams.set("uri", request.getURI());
    _requestAuthParams.set("nonce", nonce);
    _requestAuthParams.setRealm(realm);
    if (responseAuthParams.has("opaque")) {
        _requestAuthParams.set("opaque", responseAuthParams.get("opaque"));
    }

    // if (icompare(algorithm, "MD5-sess") == 0) {
    //     ha1 = digest(engine, ha1, nonce, cnonce);
    // }

    if (qop.empty()) {
        updateAuthParams(request);
    } else if (icompare(qop, "auth") == 0) {
        _requestAuthParams.set("cnonce", createNonce());
        _requestAuthParams.set("qop", qop);
        updateAuthParams(request);
    } else if (icompare(qop, "auth-int") == 0) {
        // TODO
        throw NotImplementedException("Integrity protection is not implemented");
    } else {
        throw InvalidArgumentException("Invalid quality of protection", qop);
    }
}


void HTTPDigestCredentials::updateAuthParams(const HTTPRequest& request)
{
    _requestAuthParams.set("uri", request.getURI());

    const std::string& qop = _requestAuthParams.get("qop", defaultQop);
    const std::string& nonce = _requestAuthParams.get("nonce");
    const std::string& realm = _requestAuthParams.getRealm();

    MD5Engine engine;

    if (qop.empty()) {
        const std::string ha1 = digest(engine, _username, realm, _password);
        const std::string ha2 = digest(engine, request.getMethod(), request.getURI());

        _requestAuthParams.set("response", digest(engine, ha1, nonce, ha2));
    } else if (icompare(qop, "auth") == 0) {
        const std::string& cnonce = _requestAuthParams.get("cnonce");

        const std::string ha1 = digest(engine, _username, realm, _password);
        const std::string ha2 = digest(engine, request.getMethod(), request.getURI());
        const std::string nc = formatNonceCounter(updateNonceCounter(nonce));

        _requestAuthParams.set("nc", nc);
        _requestAuthParams.set("response", digest(engine, ha1, nonce, nc, cnonce, qop, ha2));
    }
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

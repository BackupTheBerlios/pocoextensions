//
// HTTPDigestCredentials.h
//
// Copyright (c) 2011 Anton V. Yabchinskiy (arn at users dot berlios dot de)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//


#ifndef Net_HTTPDigestCredentials_INCLUDED
#define Net_HTTPDigestCredentials_INCLUDED


#include <map>


#include "Poco/Net/HTTPAuthenticationParams.h"
#include "Poco/Net/Net.h"


namespace Poco {


class DigestEngine;


namespace Net {


class HTTPRequest;
class HTTPResponse;


class Net_API HTTPDigestCredentials
	/// This is a utility class for working with
	/// HTTP Digest Authentication in HTTPRequest
	/// objects.
{
public:
	HTTPDigestCredentials();
		/// Creates an empty HTTPDigestCredentials object.

	HTTPDigestCredentials(const std::string& username, const std::string& password);
		/// Creates a HTTPDigestCredentials object with the given username and password.

	void setUsername(const std::string& username);
		/// Sets the username.

	const std::string& getUsername() const;
		/// Returns the username.

	void setPassword(const std::string& password);
		/// Sets the password.

	const std::string& getPassword() const;
		/// Returns the password.

    void authenticate(HTTPRequest& request, const HTTPResponse& response);
		/// Adds authentication information to the given HTTPRequest.

    void authenticate(HTTPRequest& request, const HTTPAuthenticationParams& responseAuthParams);
		/// Adds authentication information to the given HTTPRequest.

    void updateAuthInfo(HTTPRequest& request);
		/// TODO

	static std::string createNonce();
		/// Creates a random nonce string.

	static const std::string SCHEME;

private:
	HTTPDigestCredentials(const HTTPDigestCredentials&);
	HTTPDigestCredentials& operator = (const HTTPDigestCredentials);

    void createAuthParams(const HTTPRequest& request,
                          const HTTPAuthenticationParams& responseAuthParams);

    void updateAuthParams(const HTTPRequest& request);

    int updateNonceCounter(const std::string& nonce);

    static std::string formatNonceCounter(int counter);

    typedef std::map<std::string, int> NonceCounterMap;

    std::string _password;
    std::string _username;
    HTTPAuthenticationParams _requestAuthParams;
    NonceCounterMap _nc;
};


//
// inlines
//
inline const std::string& HTTPDigestCredentials::getUsername() const
{
	return _username;
}


inline const std::string& HTTPDigestCredentials::getPassword() const
{
	return _password;
}


} } // namespace Poco::Net


#endif // Net_HTTPDigestCredentials_INCLUDED

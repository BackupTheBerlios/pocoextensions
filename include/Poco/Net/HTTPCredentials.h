//
// HTTPCredentials.h
//
// Copyright (c) 2011 Anton V. Yabchinskiy (arn at users dot berlios dot de)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//


#ifndef Net_HTTPCredentials_INCLUDED
#define Net_HTTPCredentials_INCLUDED


#include "Poco/Net/HTTPDigestCredentials.h"


namespace Poco {


class URI;


namespace Net {


class HTTPRequest;
class HTTPResponse;


class HTTPCredentials
    /// This is a utility class for working with HTTP
    /// authentication (basic or digest) in HTTPRequest objects.
{
public:
    HTTPCredentials();
        /// Creates an empty HTTPCredentials object.

    HTTPCredentials(const std::string& username, const std::string& password);
        /// Creates an HTTPCredentials object with the given username and password.

    ~HTTPCredentials();
        /// Destroys the HTTPCredentials.

    void setUsername(const std::string& username);
        /// Sets the username.

    const std::string& getUsername() const;
        /// Returns the username.

    void setPassword(const std::string& password);
        /// Sets the password.

    const std::string& getPassword() const;
        /// Returns the password.

    void authenticate(HTTPRequest& request, const HTTPResponse& response);
        /// Inspects authenticate header of the response, initializes
        /// the internal state (in case of digest authentication) and
        /// adds required information to the given HTTPRequest.
        ///
        /// Does nothing if there is no authentication header in the
        /// HTTPResponse.

    void updateAuthInfo(HTTPRequest& request);
        /// Updates internal state (in case of digest authentication) and
        /// replaces authentication information in the request accordingly.

    void extractFromUserInfo(const std::string& userInfo);
        /// Parses username:password string and sets username and password of
        /// the credentials object.
        /// Throws SyntaxException on invalid user information.

    void extractFromURI(const URI& uri);
        /// Extracts username and password from the given URI and sets username
        /// and password of the credentials object.
        /// Does nothing if URI has no user info part.

    static bool
    isBasicCredentials(const std::string& header);
        /// Returns true if authentication header is for Basic authentication.

    static bool
    isDigestCredentials(const std::string& header);
        /// Returns true if authentication header is for Digest authentication.

    static bool
    hasBasicCredentials(const HTTPRequest& request);
        /// Returns true if Basic authentication header is present in the request.

    static bool
    hasDigestCredentials(const HTTPRequest& request);
        /// Returns true if Digest authentication header is present in the request.

    static void
    extractFromUserInfo(const std::string& userInfo, std::string& username, std::string& password);
        /// Extracts username and password from user:password information string.
        /// Throws SyntaxException on invalid user information.

    static void
    extractFromURI(const URI& uri, std::string& username, std::string& password);
        /// Extracts username and password from the given URI.

private:
    HTTPCredentials(const HTTPCredentials&);
    HTTPCredentials& operator = (const HTTPCredentials&);

    // HTTPBasicCredentials _basic;
    HTTPDigestCredentials _digest;
};


//
// inlines
//
inline void HTTPCredentials::setUsername(const std::string& username)
{
    _digest.setUsername(username);
}


inline const std::string& HTTPCredentials::getUsername() const
{
    return _digest.getUsername();
}


inline void HTTPCredentials::setPassword(const std::string& password)
{
    _digest.setPassword(password);
}


inline const std::string& HTTPCredentials::getPassword() const
{
    return _digest.getPassword();
}


} } // namespace Poco::Net


#endif // Net_HTTPCredentials_INCLUDED

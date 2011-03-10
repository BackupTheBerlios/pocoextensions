//
// HTTPAuthenticationParams.h
//
// Copyright (c) 2011 Anton V. Yabchinskiy (arn at users dot berlios dot de)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//


#ifndef Net_HTTPAuthenticationParams_INCLUDED
#define Net_HTTPAuthenticationParams_INCLUDED


#include "Poco/Net/NameValueCollection.h"
#include <string>


namespace Poco {
namespace Net {


class HTTPRequest;
class HTTPResponse;


class HTTPAuthenticationParams : public NameValueCollection
    /// Collection of name-value pairs of HTTP authentication header (i.e.
    /// "realm", "qop", "nonce" in case of digest authentication header).
{
public:
    HTTPAuthenticationParams();
		/// Creates an empty authentication parameters collection.

    explicit HTTPAuthenticationParams(const std::string& authInfo);
        /// See fromAuthInfo() documentation.

    explicit HTTPAuthenticationParams(const HTTPRequest& request);
        /// See fromRequest() documentation.

    explicit HTTPAuthenticationParams(const HTTPResponse& response);
        /// See fromResponse() documentation.

    virtual ~HTTPAuthenticationParams();
		/// Destroys the HTTPAuthenticationParams.

    HTTPAuthenticationParams& operator = (const HTTPAuthenticationParams& authParams);
		/// Assigns the content of another HTTPAuthenticationParams.

    void fromAuthInfo(const std::string& authInfo);
		/// Creates an HTTPAuthenticationParams by parsing authentication
        /// information.

    void fromRequest(const HTTPRequest& request);
		/// Extracts authentication information from the request and creates
        /// HTTPAuthenticationParams by parsing it.
        ///
        /// Throws a NotAuthenticatedException if no authentication
        /// information is contained in request.
        /// Throws a InvalidArgumentException if authentication scheme is
        /// unknown or invalid.

    void fromResponse(const HTTPResponse& response);
		/// Extracts authentication information from the response and creates
        /// HTTPAuthenticationParams by parsing it.
        ///
        /// Throws a NotAuthenticatedException if no authentication
        /// information is contained in response.
        /// Throws a InvalidArgumentException if authentication scheme is
        /// unknown or invalid.

    void setRealm(const std::string& realm);
		/// Sets the "realm" parameter to the provided string.

    const std::string& getRealm() const;
        /// Returns value of the "realm" parameter.
        ///
        /// Throws NotFoundException is there is no "realm" set in the
        /// HTTPAuthenticationParams.

    std::string toString() const;
        /// Formats the HTTPAuthenticationParams for inclusion in HTTP
        /// request or response authentication header.

    static const std::string REALM;

private:
    static void formatItem(std::string& result, ConstIterator itemIter);

    static bool mustBeQuoted(const std::string& param);

    void parse(std::string::const_iterator first, std::string::const_iterator last);
};


} } // namespace Poco::Net


#endif // Net_HTTPAuthenticationParams_INCLUDED

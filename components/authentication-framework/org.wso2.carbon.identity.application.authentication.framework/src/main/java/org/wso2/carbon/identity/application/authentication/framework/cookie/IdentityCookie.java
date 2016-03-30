package org.wso2.carbon.identity.application.authentication.framework.cookie;

import javax.servlet.http.Cookie;


public class IdentityCookie extends Cookie {

    private IdentityCookie(String name, String value) {
        super(name, value);
    }

    IdentityCookie(CookieBuilder builder)   {
        super(builder.name, builder.value);
        this.setComment(builder.comment);
        if (builder.domain != null) {
            this.setDomain(builder.domain);
        }
        this.setHttpOnly(builder.isHttpOnly);
        this.setPath(builder.path);
        this.setMaxAge(builder.maxAge);
        this.setSecure(builder.secure);
        this.setVersion(builder.version);
    }


}

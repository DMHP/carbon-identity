package org.wso2.carbon.identity.application.authentication.framework.cookie;


public class CookieBuilder {

    String name;
    String value;
    String comment;
    String domain;
    int maxAge = -1;
    String path;
    boolean secure;
    int version = 0;
    boolean isHttpOnly = false;

    public CookieBuilder(String name, String value) {
        this.name = name;
        this.value = value;
    }

    public CookieBuilder setComment(String comment) {
        this.comment = comment;
        return this;
    }

    public CookieBuilder setDomain(String domain)   {
        this.domain = domain;
        return this;
    }

    public CookieBuilder setMaxAge(int maxAge)  {
        this.maxAge = maxAge;
        return this;
    }

    public CookieBuilder setPath(String path)   {
        this.path = path;
        return this;
    }

    public CookieBuilder setSecure(boolean secure)  {
        this.secure = secure;
        return this;
    }

    public CookieBuilder setVersion(int version)    {
        this.version = version;
        return this;
    }

    public CookieBuilder setHttpOnly(boolean isHttpOnly)    {
        this.isHttpOnly = isHttpOnly;
        return this;
    }

    public IdentityCookie build()   {
        return new IdentityCookie(this);
    }
}

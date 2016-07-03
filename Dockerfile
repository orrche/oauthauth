FROM fedora
MAINTAINER Kent Gustavsson <kent@minoris.se>

RUN dnf update -y
RUN mkdir -p /opt/oauthauth

ADD config.toml /opt/oauthauth/
ADD oauthauth /opt/oauthauth/

RUN adduser oauthauth

USER oauthauth

EXPOSE 8080
ENTRYPOINT ["/opt/oauthauth/oauthauth"]


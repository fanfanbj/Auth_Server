# Flex Authentication And Authorization Service

This service will provide central authentication and authorization supports for Docker registry v2.0 and flex-opsmanager.

Supported authentication methods:

* 	Static list of users
* 	LDAP bind

Supported authorization methods:

* Static ACL

# Build and Installation

	# make deps
	# make build
	
	# cd cert 
	# openssl req -newkey rsa:4096 -nodes -sha256 -keyout auth.key -x509 -days 365 -out auth.crt
	# edit /config/simple.yml for certificaties and other settings.
	
	# ./bin/flex-auth-service --v=2 --alsologtostderr /config/simple.yml #for static user auth.



# Testing

	curl -H "Authorization: Basic $(echo "admin:badmin" | base64)" -vk "https://127.0.0.1:5001/auth?service=registry2:5000&scope=registry:catalog:*"
	
	
# Plans


* build a docker image for this auth service.
* complete LDAP authentication.

# Refer to

* https://github.com/cesanta/docker_auth
* https://github.com/kwk/docker-registry-setup


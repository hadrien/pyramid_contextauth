pyramid_contextauth
###################

A simple pyramid extension to provides contexts based authentication policy.
To register authentication methods::

    from pyramid.security import remember, forget

    class Context(object):
        pass

    def authenticated_userid(request):
        return unauthenticated_userid(request)

    def unauthenticated_userid(request):
        "A dummy example"
        return request.POST.get('userid')

    def effective_principals(request):
        if unauthenticated_userid(request):
            return ['User']
        return []

    def includeme(config):
        from pyramid_contextauth import get_authentication_policy
        policy.register_context(
            Context,
            authenticated_userid,
            unauthenticated_userid,
            effective_principals,
            remember,
            forget
            )

===================
pyramid_contextauth
===================

.. image:: https://travis-ci.org/hadrien/pyramid_contextauth.svg
   :target: https://travis-ci.org/hadrien/pyramid_contextauth

.. image:: https://pypip.in/d/pyramid_contextauth/badge.png
   :target: https://crate.io/packages/pyramid_contextauth/

A simple pyramid extension to provides contexts based authentication policy.

.. code-block:: python

    from pyramid.security import remember, forget
    from pyramid.authentication import AuthTktAuthenticationPolicy

    def includeme(config):
        config.include('pyramid_contextauth')
        config.register_authentication_policy(
            AuthTktAuthenticationPolicy('secret'),
            Context1,
        )
        config.register_authentication_policy(
            ContextAuthenticationPolicy(),
            (Context2, Context3),
        )


    class Context1(object):
        pass


    class Context2(object):
        pass


    class Context3(object):
        pass


    class ContextAuthenticationPolicy(object):

        def authenticated_userid(self, request):
            return unauthenticated_userid(request)

        def unauthenticated_userid(self, request):
            "A dummy example"
            return request.POST.get('userid')

        def effective_principals(self, request):
            if self.unauthenticated_userid(request):
                return ['User']
            return []

        def remember(self, request, prinicpal, **kw):
            return remember(request, prinicpal, **kw)

        def forget(self, request):
            return forget(request)

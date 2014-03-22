from pyramid.authentication import (
    AuthTktAuthenticationPolicy,
    BasicAuthAuthenticationPolicy,
)

from pyramid_contextauth import authentication_policy


def includeme(config):
    config.include('pyramid_contextauth')
    config.register_authentication_policy(
        AuthTktAuthenticationPolicy('secret'),
        Context1,
    )
    config.register_authentication_policy(
        BasicAuthAuthenticationPolicy('realm'),
        Context2,
    )
    config.scan()


class Context1(object):
    pass


class Context2(object):
    pass


class Context3(object):
    pass


class Context4(object):
    pass


@authentication_policy(Context3, Context4)
class Context3Policy(object):
    pass

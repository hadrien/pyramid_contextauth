import unittest

import mock

from pyramid.authentication import (
    AuthTktAuthenticationPolicy,
    BasicAuthAuthenticationPolicy,
)
from pyramid.config import Configurator


class TestConfig(unittest.TestCase):

    def test_get_policy(self):
        import example
        from pyramid_contextauth import get_authentication_policy

        config = Configurator(settings={})
        config.include('pyramid_contextauth')
        config.include('example')

        policy = get_authentication_policy(config)

        request = mock.Mock()
        request.registry = config.registry

        request.context = example.Context1()

        self.assertIsInstance(policy._get_policy(request),
                              AuthTktAuthenticationPolicy)

        request.context = example.Context2()

        self.assertIsInstance(policy._get_policy(request),
                              BasicAuthAuthenticationPolicy)

        request.context = example.Context3()

        self.assertIsInstance(policy._get_policy(request),
                              example.Context3Policy)

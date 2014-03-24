import unittest

import mock

from pyramid.config import Configurator


class TestConfig(unittest.TestCase):

    def _get_config(self):
        config = Configurator(settings={})
        config.include('pyramid_contextauth')
        return config

    def test_get_policy(self):
        from pyramid_contextauth import (
            get_authentication_policy,
            ContextBasedAuthenticationPolicy,
            )
        config = self._get_config()
        config.commit()
        policy = get_authentication_policy(config)
        self.assertIsInstance(policy, ContextBasedAuthenticationPolicy)


class TestPyramidContextAuth(unittest.TestCase):

    def setUp(self):
        self.config = Configurator(settings={})

    def _get_policy(self):
        from pyramid_contextauth import ContextBasedAuthenticationPolicy
        return ContextBasedAuthenticationPolicy()

    def _get_context_class(self, name):
        return type(name, (object, ), {})

    def test_call_method_no_context(self):
        A = self._get_context_class('A')
        request = mock.Mock()
        request.context = A()
        request.registry = self.config.registry

        policy = self._get_policy()

        self.assertIsNone(policy._call_method(request, 'authenticated_userid'))

    def test_call_method_no_authenticated_userid_method(self):
        A = self._get_context_class('A')
        request = mock.Mock()
        request.context = A()
        request.registry = self.config.registry
        ctx_policy = type('Policy', (object, ), {})

        policy = self._get_policy()

        policy.register_policy(self.config, ctx_policy, A)

        self.assertEqual(None, policy.authenticated_userid(request))

    def test_call_method_no_effective_principals(self):
        A = self._get_context_class('A')
        request = mock.Mock()
        request.context = A()
        request.registry = self.config.registry
        ctx_policy = type('Policy', (object, ), {})

        policy = self._get_policy()

        policy.register_policy(self.config, ctx_policy, A)
        # should call CallbackAuthenticationPolicy.authenticated_userid_method
        # wich rely on unauthenticated_id (m1)

        self.assertEqual(['system.Everyone'],
                         policy.effective_principals(request))

    def test_authenticated_methods(self):
        A = self._get_context_class('A')
        ctx_policy = mock.Mock()
        request = mock.Mock()
        request.context = A()
        request.registry = self.config.registry

        policy = self._get_policy()

        policy.register_policy(self.config, ctx_policy, A)

        self.assertEqual(ctx_policy.authenticated_userid.return_value,
                         policy.authenticated_userid(request))

        self.assertEqual(ctx_policy.unauthenticated_userid.return_value,
                         policy.unauthenticated_userid(request))

    def test_effective_principals(self):
        A = self._get_context_class('A')
        request = mock.Mock()
        ctx_policy = mock.Mock()
        request.context = A()
        request.registry = self.config.registry
        policy = self._get_policy()

        ctx_policy.unauthenticated_userid.return_value = '123'
        ctx_policy.effective_principals.return_value = ['1234567']

        policy.register_policy(self.config, ctx_policy, A)

        expected = ['system.Everyone', 'system.Authenticated', '123',
                    '1234567']
        self.assertEqual(expected, policy.effective_principals(request))

    def test_remember_forget(self):
        A = self._get_context_class('A')
        request = mock.Mock()
        request.context = A()
        request.registry = self.config.registry
        policy = self._get_policy()

        ctx_policy = mock.Mock()
        ctx_policy.forget.return_value = ['Header']
        ctx_policy.remember.return_value = ['Header']

        policy.register_policy(self.config, ctx_policy, A)

        self.assertEqual(['Header'],
                         policy.remember(request,
                                         ['system.Everyone', '1234567']))
        self.assertEqual(['Header'], policy.forget(request))

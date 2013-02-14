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

    def _get_policy(self):
        from pyramid_contextauth import ContextBasedAuthenticationPolicy
        return ContextBasedAuthenticationPolicy()

    def _get_context_class(self, name):
        return type(name, (object, ), {})

    def _get_methods(self):
        return (mock.Mock(), mock.Mock(), mock.Mock(), mock.Mock(),
                mock.Mock())

    def test_call_method(self):
        A = self._get_context_class('A')

        m0, m1, m2, m3, m4 = self._get_methods()

        request = mock.Mock()
        request.context = A()

        policy = self._get_policy()

        policy.register_context(A, m0, m1, m2, m3, m4)

        # check if method index are consistent
        for i in range(5):
            methods = [m0, m1, m2, m3, m4]
            # only method at index i must be called
            result = policy._call_method(request, i)

            self.assertEqual(methods[i].return_value, result)

            methods[i].assert_called_once_with(request)

            m = methods.pop(i)

            for m in methods:
                # check other methods have NOT been called
                self.assertEqual(0, m.call_count)

            # reset mock:
            [_.reset_mock() for _ in [m0, m1, m2, m3, m4]]

    def test_call_method_no_context(self):
        A = self._get_context_class('A')
        request = mock.Mock()
        request.context = A()

        policy = self._get_policy()

        self.assertIsNone(policy._call_method(request, 0))

    def test_call_method_no_method(self):
        A = self._get_context_class('A')
        request = mock.Mock()
        request.context = A()
        m0, m1, m2, m3, m4 = self._get_methods()

        policy = self._get_policy()
        policy.register_context(A, None, m1, m2, m3, m4)

        self.assertIsNone(policy._call_method(request, 0))

    def test_authenticated_methods(self):
        A = self._get_context_class('A')
        request = mock.Mock()
        request.context = A()
        policy = self._get_policy()

        auth_method = mock.Mock()

        policy.register_context(A, auth_method, auth_method, None, None, None)

        self.assertEqual(auth_method.return_value,
                         policy.authenticated_userid(request))

        self.assertEqual(auth_method.return_value,
                         policy.unauthenticated_userid(request))

    def test_effective_principals(self):
        A = self._get_context_class('A')
        request = mock.Mock()
        request.context = A()
        policy = self._get_policy()

        effective_principals = mock.Mock()
        effective_principals.return_value = ['1234567']

        policy.register_context(A, None, None, effective_principals, None,
                                None)

        expected = ['system.Everyone', '1234567']
        self.assertEqual(expected, policy.effective_principals(request))

    def test_remember_forget(self):
        A = self._get_context_class('A')
        request = mock.Mock()
        request.context = A()
        policy = self._get_policy()

        method = mock.Mock()
        method.return_value = ['Header']

        policy.register_context(A, None, None, None, method, method)

        self.assertEqual(['Header'],
                         policy.remember(request,
                                         ['system.Everyone', '1234567']))
        self.assertEqual(['Header'], policy.forget(request))

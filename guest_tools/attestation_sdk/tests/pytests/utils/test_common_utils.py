import unittest

import time

from verifier.utils import function_wrapper_with_timeout
from verifier.exceptions import TimeoutError


class CommonUtilsTest(unittest.TestCase):

    def test_timeout_returns(self):
        def incrementer(x):
            return x + 1

        self.assertEqual(
            function_wrapper_with_timeout([incrementer, 1, "incrementer"], 1),
            2,
            "return value of task is returned"
        )

    def test_timeout_is_raised(self):
        with self.assertRaises(TimeoutError):
            start = time.monotonic()
            function_wrapper_with_timeout([time.sleep, 2, "sleep"], 0.1)
        duration = time.monotonic() - start
        self.assertLess(duration, 1, "should time out before function would return")

    def test_inner_exception(self):
        class CustomException(BaseException):
            pass

        def raiser():
            raise CustomException()

        with self.assertRaises(CustomException):
            start = time.monotonic()
            function_wrapper_with_timeout([raiser, "raiser"], 2)
        duration = time.monotonic() - start
        self.assertLess(duration, 1, "should return exception quickly and not wait")

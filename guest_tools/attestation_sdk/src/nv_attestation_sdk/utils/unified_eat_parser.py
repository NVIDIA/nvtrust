#
# Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

"""
Utility functions for EAT token parsing.
"""


def get_overall_token_type(token: list) -> str:
    """
    Get the overall token type from a list of tokens.

    :param token: A list of tokens.
    :return: The type of the overall token.
    """
    overall_token_arr = token[0]
    return overall_token_arr[0]


def get_overall_claims_token(token: list) -> str:
    """
    A function that takes a list as input and returns a string.
    It extracts the second element of the first list in the input list.
    """
    overall_token_arr = token[0]
    return overall_token_arr[1]


def get_detached_claims_token(token: list) -> str:
    """
    A function that takes in a list as a parameter and returns the element at index 1.
    Parameters:
        token (list): The input list.
    Returns:
        str: The element at index 1 of the input list.
    """
    return token[1]

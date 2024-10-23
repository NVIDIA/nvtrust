#
# Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

def get_overall_token_type(token: list) -> str:
    overall_token_arr = token[0]
    return overall_token_arr[0]


def get_overall_claims_token(token: list) -> str:
    overall_token_arr = token[0]
    return overall_token_arr[1]


def get_detached_claims_token(token: list) -> str:
    return token[1]

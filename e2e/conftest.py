"""
Shared pytest fixtures for EIP-8141 E2E test suites.
"""

import pytest
from web3 import Web3


RPC_URL = "http://localhost:8545"


@pytest.fixture(scope="session")
def w3():
    """Web3 connection to local anvil node."""
    provider = Web3(Web3.HTTPProvider(RPC_URL))
    if not provider.is_connected():
        pytest.skip(
            f"Cannot connect to {RPC_URL}. "
            "Start anvil first: cd foundry && cargo run -p anvil -- --chain-id 8141"
        )
    return provider


@pytest.fixture(scope="session")
def chain_id(w3):
    return w3.eth.chain_id


@pytest.fixture(scope="session")
def funder(w3):
    return w3.eth.accounts[0]


@pytest.fixture(scope="session")
def recipient(w3):
    return w3.eth.accounts[1]

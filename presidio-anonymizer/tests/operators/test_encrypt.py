from unittest import mock

import pytest

from presidio_anonymizer.operators import Encrypt, AESCipher
from presidio_anonymizer.entities import InvalidParamError


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_then_aes_encrypt_called_and_its_result_is_returned(
    mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": "key"})

    assert anonymized_text == expected_anonymized_text


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_with_bytes_key_then_aes_encrypt_result_is_returned(
        mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text",
                                        params={"key": b'1111111111111111'})

    assert anonymized_text == expected_anonymized_text


def test_given_verifying_an_valid_length_key_no_exceptions_raised():
    Encrypt().validate(params={"key": "128bitslengthkey"})


def test_given_verifying_an_valid_length_bytes_key_no_exceptions_raised():
    Encrypt().validate(params={"key": b'1111111111111111'})


def test_given_verifying_an_invalid_length_key_then_ipe_raised():
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": "key"})

# Grading Task 3
# 3.1 have the method `test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised`
# 3.2 changed the patch object in line 53 to `is_valid_key_size`
# 3.3 changed the mock_encrypt at line 55 to something appropriate (e.g. mock_is_valid_key_size)
# 3.4 add the return value to the mocked method (e.g. line 58)
# 3.5 the coverage report for encrypt.py should be 100%

@mock.patch.object(AESCipher, "is_valid_key_size") # hint: replace encrypt with the method that you want to mock
def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised(mock_is_valid_key_size): # hint: replace mock_encrypt with a proper name for your mocker
    # Here: add setup for mocking
    mock_is_valid_key_size.return_value = False
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": b'1111111111111111'})

# Grading Task 2
# 2.1 have the method `test_operator_name`
   # 2.1.1 correctly cover the line in operator_name method
# 2.2 have the method `test_operator_type`
   # 2.2.1 correctly cover the line in operator_type method
# 2.3 the coverage report for encrypt.py should be 94%

def test_operator_name():
    assert Encrypt().operator_name() == "encrypt"

from presidio_anonymizer.operators import OperatorType
def test_operator_type():
    assert Encrypt().operator_type() == OperatorType.Anonymize


# Grading Task 4
# 4.1 have the test method `test_valid_keys`
# 4.2 should have parametrize right before the method signature
# 4.3 have six input cases for the parametrize
# 4.4 the six input cases should satisfy (may be out of order):
#-	A string key with 128 bits
#-	A string key with 192 bits
#-	A string key with 256 bits
#-	A bytes key with 128 bits
#-	A bytes key with 192 bits
#-	A bytes key with 256 bits
# 4.5 in the test body, call the validate method with the input
@pytest.mark.parametrize(
    # fmt: off
    "key",
    [
        "128bitslengthkey",
        "192bitslengthkey12345678",
        "256bitslengthkey256bitslengthkey",
        b'1111111111111111',
        b'111111111111111112345678',
        b'11111111111111111111111111111111'
    ],
    # fmt: on
)
def test_valid_keys(key):
    Encrypt().validate(params={"key": key})
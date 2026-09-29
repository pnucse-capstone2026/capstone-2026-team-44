from payload_verifier.mutation import (
    replace_query_parameter,
)


def test_replace_existing_query_parameter() -> None:
    result = replace_query_parameter(
        url=(
            "http://127.0.0.1:8899/"
            "product?id=42&lang=ko"
        ),
        parameter_name="id",
        new_value="43",
    )

    assert (
        result
        == (
            "http://127.0.0.1:8899/"
            "product?id=43&lang=ko"
        )
    )


def test_add_missing_query_parameter() -> None:
    result = replace_query_parameter(
        url=(
            "http://127.0.0.1:8899/"
            "product"
        ),
        parameter_name="id",
        new_value="42",
    )

    assert (
        result
        == (
            "http://127.0.0.1:8899/"
            "product?id=42"
        )
    )

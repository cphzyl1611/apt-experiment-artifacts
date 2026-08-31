from __future__ import annotations


def test_set_external_seed_repeats_python_numpy_and_torch_streams():
    from control_seed_wrapper import set_external_seed

    set_external_seed(123)
    first = __import__("random").random()
    first_numpy = __import__("numpy").random.random()
    first_torch = __import__("torch").rand(3).tolist()

    set_external_seed(123)
    second = __import__("random").random()
    second_numpy = __import__("numpy").random.random()
    second_torch = __import__("torch").rand(3).tolist()

    assert first == second
    assert first_numpy == second_numpy
    assert first_torch == second_torch

"""
Golden тесты транслятора ассемблера и машины.

Конфигурационные файлы: "golden/*_asm.yml"
"""

import contextlib
import io
import logging
import os
import tempfile

import machine
import pytest
import translator


@pytest.mark.golden_test("./python/golden/*.yml")
def test_translator_asm_and_machine(golden, caplog):
    caplog.set_level(logging.DEBUG)

    with tempfile.TemporaryDirectory() as tmpdirname:
        source = os.path.join(tmpdirname, "source.asm")
        input_stream = os.path.join(tmpdirname, "input.txt")
        target = os.path.join(tmpdirname, "target.o")
        target_debug = os.path.join(tmpdirname, "target.o.debug")

        with open(source, "w", encoding="utf-8") as file:
            file.write(golden["in_source"])
        with open(input_stream, "w", encoding="utf-8") as file:
            file.write(golden["in_stdin"])

        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            translator.main(source, target, target_debug)
            machine.main(target, input_stream)

        with open(target_debug, encoding="utf-8") as file:
            code = file.read()

        print(code == golden.out["out_code_debug"])

        '''
        assert code.replace(" ", "") == golden.out["out_code_debug"].replace(" ", "")
        assert stdout.getvalue().replace(" ", "") == golden.out["out_stdout"].replace(" ", "")
        assert caplog.text.replace(" ", "") == golden.out["out_log"].replace(" ", "")
        '''

#!/usr/bin/python3
"""Транслятор asm в машинный код.

program ::= { line }

line ::= label [ comment ] "\n"
       | instr [ comment ] "\n"
       | [ comment ] "\n"

label ::= label_name ":"

instr ::= op0
        | op1 label_name

op0 ::= "inc"
      | "dec"
      | "in"
      | "out"

op1 ::= "jmp"
      | "jz"

integer ::= [ "-" ] { <any of "0-9"> }-

label_name ::= <any of "a-z A-Z _"> { <any of "a-z A-Z 0-9 _"> }

comment ::= ";" <any symbols except "\n">

"""

import re
import sys

from isa import Opcode, Term, op_has_no_args, DataTypeDirective, OrgDirective, Registers, \
    op_has_1_arg, InstructionPostfix, op_has_2_args, op1_arg_for_w, InstructionPrefix, ByteCodeFile


def data_dict(type, value):
    return {"type": type, "value": value}


def str_to_number(number):
    neg = number[0] == "-"
    if neg:
        number = number[1:]

    if number[:2] == "0x":
        value, base = int(number, 16), 16
    else:
        value, base = int(number), 10

    if (base == 16) and (hex(value) != number) or (base == 10) and (str(value) != number):
        raise Exception("Странное какое-то число: {}".format(number))

    return value, base


class Parser:
    """
    Очень большой и очень страшный парсер на все случаи жизни.

    Позволяет понять, есть ли в строке:

    - директива "org"
    - директива данных ("byte", "word") с аргументами
    - одиночная метка
    - [метка] инструкция [[директива] аргумент]*

    Также содержит все необходимые методы для поиска элементов языка в подстроке
    """

    org_directive = OrgDirective.ORG
    type_directives = [DataTypeDirective.BYTE, DataTypeDirective.WORD]
    number_regex = re.compile(r"([\-\+]?0x[\da-f]+|\d+)")
    string_regex = re.compile(r"(\'[^\']+\')")
    label_name_regex = re.compile(r"([_\.a-z][_\.\da-z]*)")
    org_directive_regex = re.compile(r"org *(0x[\da-f]+|\d+)")
    general_purpose_registers = Registers.code_to_register_list

    available_mnemonics = {
        "nop": Opcode.NOP.value,
        "halt": Opcode.HALT.value,
        "clc": Opcode.CLC.value,
        "cmc": Opcode.CMC.value,
        "pushf": Opcode.PUSHF.value,
        "popf": Opcode.POPF.value,
        "ei": Opcode.EI.value,
        "di": Opcode.DI.value,
        "ret": Opcode.RET.value,
        "iret": Opcode.IRET.value,
        "not": Opcode.NOT.value,
        "neg": Opcode.NEG.value,
        "inc": Opcode.INC.value,
        "dec": Opcode.DEC.value,
        "rol": Opcode.ROL.value,
        "ror": Opcode.ROR.value,
        "asl": Opcode.ASL.value,
        "asr": Opcode.ASR.value,
        "sxtb": Opcode.SXTB.value,
        "swab": Opcode.SWAB.value,
        "jmp": Opcode.JMP.value,
        "jl": Opcode.JL.value,
        "jle": Opcode.JLE.value,
        "je": Opcode.JE.value,
        "jne": Opcode.JNE.value,
        "jg": Opcode.JG.value,
        "jge": Opcode.JGE.value,
        "loop": Opcode.LOOP.value,
        "push": Opcode.PUSH.value,
        "pop": Opcode.POP.value,
        "call": Opcode.CALL.value,
        "int": Opcode.INT.value,
        "mov": Opcode.MOV.value,
        "and": Opcode.AND.value,
        "or": Opcode.OR.value,
        "xor": Opcode.XOR.value,
        "add": Opcode.ADD.value,
        "adc": Opcode.ADC.value,
        "sub": Opcode.SUB.value,
        "mul": Opcode.MUL.value,
        "div": Opcode.DIV.value,
        "cmp": Opcode.CMP.value,
        "swap": Opcode.SWAP.value,
        "poly": Opcode.POLY.value
    }

    key_words = set(list(available_mnemonics.keys()) + list(org_directive) + list(type_directives))

    @staticmethod
    def is_string(symbol):
        match = Parser.string_regex.match(symbol)

        if match is None:
            return False

        return match.string == symbol

    @staticmethod
    def is_number(symbol):
        match = Parser.number_regex.match(symbol)

        if match is None:
            return False

        return match.string == symbol

    @staticmethod
    def is_hex(symbol):
        return Parser.is_number(symbol) and symbol[:2] == "0x"

    @staticmethod
    def is_dec(symbol):
        return Parser.is_number(symbol) and symbol[:2] != "0x"

    @staticmethod
    def is_label_name(symbol):
        symbol = str(symbol)

        match = Parser.label_name_regex.match(symbol)

        if match is None:
            return False

        return match.string == symbol

    @staticmethod
    def symbol_to_opcode(symbol):
        """Отображение операторов исходного кода в коды операций."""
        return Parser.available_mnemonics.get(symbol)

    @staticmethod
    def try_find_label_name(line: str):
        match = Parser.label_name_regex.match(line)

        if match is None:
            raise Exception("`{}` - не метка".format(line))

        label_name = match.group(1)
        if label_name.find("..") >= 0:
            raise Exception("В имени метки не может идти две `.` подряд")

        return label_name, line[match.end(1):].lstrip(" ")

    @staticmethod
    def parser_label_with_colon(line: str, add_colon=False):
        label_name, line = Parser.try_find_label_name(line)

        if len(line) == 0 or line[0] != ":":
            raise Exception("Метка должна кончаться на `:`")

        return label_name + (":" if add_colon else ""), line[1:].lstrip(" ")

    @staticmethod
    def try_find_type_directive(line: str):
        line = line.lstrip(" ")

        pos = line.find(" ")

        if pos < 0:
            raise Exception("После директивы данных ожидался пробел")

        directive = line[:pos]

        if directive not in Parser.type_directives:
            raise Exception("`{}` - не директива, можно так = {}".format(directive, Parser.type_directives))

        return directive, line[pos:].lstrip(" ")

    @staticmethod
    def try_find_number(line: str):
        line = line.lstrip(" ")

        match = Parser.number_regex.match(line)

        if match is None:
            raise Exception("`{}` - не число, можно так = [0x0123456789ABCDEF, 0123456789]".format(line))

        return match.group(1).lstrip("+"), line[match.end(1):].lstrip(" ")

    @staticmethod
    def try_find_string(line: str):
        line = line.lstrip(" ")

        match = Parser.string_regex.match(line)

        if match is None:
            raise Exception("`{}` - не строка, можно так = r\"'[^\']+'\"".format(line))

        return match.group(1), line[match.end(1):].lstrip(" ")

    @staticmethod
    def try_find_data_args(line: str):
        args = []
        found_one = False

        try:
            dup, line = Parser.try_find_dup(line)
            args.extend(dup)
            found_one = True
        except Exception as e:
            pass

        try:
            label_name, line = Parser.try_find_label_name(line)
            args.append(label_name)
            found_one = True
        except Exception as e:
            pass

        try:
            number, line = Parser.try_find_number(line)
            args.append(number)
            found_one = True
        except Exception as e:
            pass

        try:
            string, line = Parser.try_find_string(line)
            args.append(string)
            found_one = True
        except Exception as e:
            pass

        if not found_one:
            raise Exception("После директивы ожидались данные")

        if len(line) > 0:
            if line[0] == ",":
                new_args, line = Parser.try_find_data_args(line[1:].lstrip(" "))
                args.extend(new_args)

        return args, line

    @staticmethod
    def try_find_dup(line: str):
        try:
            number, line = Parser.try_find_number(line)
        except Exception as e:
            raise Exception("Перед `dup` ожидалось число")

        pos = 3
        dup = line[:pos]

        if dup != "dup":
            raise Exception("После числа ожидалось `dup`")

        line = line[pos:].lstrip(" ")

        if line[0] != "(":
            raise Exception("После dup ожидалось `(`")

        line = line[1:].lstrip(" ")

        args, line = Parser.try_find_data_args(line)
        line = line.lstrip(" ")

        if line[0] != ")":
            raise Exception("После аргументов ожидалось `)`")

        if number.find("0x") >= 0:
            number = int(number, 16)
        else:
            number = int(number)

        return args * number, line[1:].lstrip(" ")

    @staticmethod
    def try_find_instruction(line: str):
        pos = line.find(" ")
        if pos < 0:
            pos = len(line)

        instruction = line[:pos]

        if instruction not in Parser.available_mnemonics:
            raise Exception("`{}` не мнемоника инструкции".format(instruction))

        return instruction, line[pos:].lstrip(" ")

    @staticmethod
    def try_find_instruction_args(line: str):
        args = []
        found_one = False

        try:
            directive, line = Parser.try_find_type_directive(line)
            args.append(directive)
            found_one = True
        except Exception as e:
            pass

        try:
            base, index_sign, index, scale_factor, offset_sign, offset, line = Parser.try_find_memory_addressing(line)
            args.append({"base": base, "index_sign": index_sign, "index": index, "scale_factor": scale_factor,
                         "offset_sign": offset_sign, "offset": offset})
            found_one = True
        except Exception as e:
            pass

        try:
            reg, line = Parser.try_find_register(line)
            args.append(reg)
            found_one = True
        except Exception as e:
            pass

        try:
            label_name, line = Parser.try_find_label_name(line)
            args.append(label_name)
            found_one = True
        except Exception as e:
            pass

        try:
            number, line = Parser.try_find_number(line)
            args.append(number)
            found_one = True
        except Exception as e:
            pass

        try:
            string, line = Parser.try_find_string(line)
            args.append(string)
            found_one = True
        except Exception as e:
            pass

        if not found_one:
            raise Exception("После инструкции ожидались аргументы")

        if len(line) > 0:
            if line[0] == ",":
                new_args, line = Parser.try_find_instruction_args(line[1:].lstrip(" "))
                args.extend(new_args)

        return args, line

    @staticmethod
    def try_find_register(line: str):
        for register in Parser.general_purpose_registers:
            if line[:len(register)] == register:
                return register, line[len(register):].lstrip(" ")

        raise Exception("Ожидался регистр, регистры общего назначения = {}".format(Parser.general_purpose_registers))

    @staticmethod
    def try_find_address_base(line: str):
        try:
            number, line = Parser.try_find_number(line)
            return number, line
        except Exception:
            pass

        try:
            reg, line = Parser.try_find_register(line)
            return reg, line
        except Exception:
            pass

        try:
            label, line = Parser.try_find_label_name(line)
            return label, line
        except Exception:
            pass

        raise Exception("Ожидалось основание адреса (число, метка, регистр)")

    @staticmethod
    def try_find_addressing_sign(line: str):
        if (line[0] == "-") or (line[0] == "+"):
            return line[0], line[1:].lstrip(" ")

        return "+", line

    @staticmethod
    def try_find_array_index(line: str):
        sign, line = Parser.try_find_addressing_sign(line)
        index, line = Parser.try_find_register(line)
        scale_factor, line = Parser.try_find_number(line[1:])

        number = int(scale_factor)
        max_number = InstructionPostfix.get_scale_factor_max_pow()
        if (number <= 0) or (number > 1 << max_number):
            raise Exception("`{}` - плохой `scale factor`, можно: {}".format(scale_factor, [(1 << i) for i in range(int(max_number) + 1)]))

        return sign, index, scale_factor, line

    @staticmethod
    def try_find_address_offset(line: str):
        sign, line = Parser.try_find_addressing_sign(line)

        try:
            number, line = Parser.try_find_number(line)
            return sign, number, line
        except Exception:
            pass

        try:
            reg, line = Parser.try_find_register(line)
            return sign, reg, line
        except Exception:
            pass

        raise Exception("Ожидалось смещение адреса (число, регистр)")

    @staticmethod
    def try_find_memory_addressing(line):
        if line[0] != "[":
            raise Exception("Адресация памяти начинается с `[`")

        line = line[1:].lstrip(" ")

        base, line = Parser.try_find_address_base(line)

        try:
            index_sign, index, scale_factor, line = Parser.try_find_array_index(line)
        except Exception:
            index_sign, index, scale_factor = None, None, None

        try:
            offset_sign, offset, line = Parser.try_find_address_offset(line)
        except Exception:
            offset_sign, offset = None, None

        if line[0] != "]":
            raise Exception("Адресация памяти заканчивается на `]`")

        return base, index_sign, index, scale_factor, offset_sign, offset, line[1:].strip(" ")

    @staticmethod
    def parse_org(line: str):
        match = Parser.org_directive_regex.match(line)

        if match is None:
            raise Exception("`{}` - не директива `org`".format(line))

        return match.group(1), line[match.end(1):]

    @staticmethod
    def parse_data_def(line: str):
        try:
            label, line = Parser.parser_label_with_colon(line)
        except Exception as e:
            label = None

        directive, line = Parser.try_find_type_directive(line)
        args, line = Parser.try_find_data_args(line)

        return label, directive, args

    @staticmethod
    def parse_instruction(line: str):
        try:
            label, line = Parser.parser_label_with_colon(line)
        except Exception as e:
            label = None
            pass

        directive = DataTypeDirective.WORD
        instruction, line = Parser.try_find_instruction(line)

        if op_has_no_args(Parser.symbol_to_opcode(instruction)):
            return label, directive, instruction, []

        args = []
        try:
            args, line = Parser.try_find_instruction_args(line)
        except Exception as e:
            pass

        if DataTypeDirective.BYTE in args:
            # если есть хоть одна директива `byte` то все операнды вынуждены приводиться к байту
            # это не будет касаться подсчета адреса, для них всегда `word`
            args = [arg for arg in args if arg not in Parser.type_directives]
            directive = DataTypeDirective.BYTE

        return label, directive, instruction, args


def arg_is_number_register_label_or_memory(arg):
    is_memory = isinstance(arg, dict)

    if is_memory:
        return False, False, False, is_memory

    is_number = Parser.is_number(arg)
    is_register = arg in Parser.general_purpose_registers
    is_label = (not is_register) and Parser.is_label_name(arg)

    return is_number, is_register, is_label, is_memory


def encode_instruction_arg(directive, arg):
    max_uint = DataTypeDirective.get_max_uint(directive)
    data = []

    is_number, is_register, is_label, is_memory = arg_is_number_register_label_or_memory(arg)

    if is_label:
        data.append(data_dict(DataTypeDirective.BYTE, InstructionPostfix.ArgIsImmediate))
        data.append(data_dict(DataTypeDirective.WORD, arg))
    elif is_number:
        data.append(data_dict(DataTypeDirective.BYTE, InstructionPostfix.ArgIsImmediate))

        number, base = str_to_number(arg)
        if number > max_uint:
            number = number & max_uint

        arg = ("-" if arg[0] == "-" else "") + (hex(number) if base == 16 else str(number))

        if arg[0] == "-":
            number = max_uint + 1 - number

        data.append(data_dict(directive, number))
    elif is_register:
        data.append(data_dict(DataTypeDirective.BYTE, InstructionPostfix.encode_register(arg)))
    else:
        has_offset = arg["offset"] is not None
        has_index = arg["index"] is not None
        scale_factor = (arg["scale_factor"] is not None) and (arg["scale_factor"] == "2")
        offset_sign = (arg["offset_sign"] is not None) and (arg["offset_sign"] == "-")
        index_sign = (arg["index_sign"] is not None) and (arg["index_sign"] == "-")

        data.append(data_dict(DataTypeDirective.BYTE, InstructionPostfix.encode_addressing_mode(has_offset, has_index, scale_factor, offset_sign, index_sign)))

        byte_code, arg["base"] = encode_instruction_arg(DataTypeDirective.WORD, arg["base"])
        data.extend(byte_code)

        if has_index:
            byte_code, arg["index"] = encode_instruction_arg(DataTypeDirective.WORD, arg["index"])
            data.extend(byte_code)

        if has_offset:
            byte_code, arg["offset"] = encode_instruction_arg(DataTypeDirective.WORD, arg["offset"])
            data.extend(byte_code)

        arg_str = arg["base"]
        if has_index:
            arg_str += ("-" if index_sign else "+") + arg["index"] + "*" + arg["scale_factor"]

        if has_offset:
            arg_str += ("-" if offset_sign else "+") + arg["offset"]

        arg = "[" + arg_str + "]"

    return data, arg


def get_meaningful_token(line):
    """
    Извлекаем из строки содержательный токен (метка или инструкция), удаляем
    комментарии и пробелы в начале/конце строки.
    """
    return line.split(";", 1)[0].strip()


def translate_stage_1(text):
    """
    Первый проход транслятора. Преобразование текста программы в список
    инструкций.
    """

    def check_new_label(label, last_root_label):
        if label is None or len(label) == 0:
            return label, last_root_label

        if label[0] == ".":
            # локальный для последнего глобального
            label = last_root_label + label
        else:
            last_root_label = label

        assert label not in Parser.key_words, "Нельзя назначить метку `{}` с именем ключевого слова".format(label)

        assert label not in labels, "Переопределение метки: {}".format(label)
        labels[label] = -1

        return label, last_root_label

    code = []
    labels = {}
    last_root_label = ""
    entry_point_label = "start"

    for line_num, raw_line in enumerate(text.splitlines(), 1):
        token = get_meaningful_token(raw_line)
        if token == "":
            continue

        if token.endswith(":"):
            # токен содержит только метку
            try:
                label, line = Parser.parser_label_with_colon(token)

                if len(line) > 0:
                    raise Exception("`{}` чему лишние `:` в конце строки?".format(token))

                label, last_root_label = check_new_label(label, last_root_label)

                code.append({"mem_address": 0, "label": label, "term": Term(line_num, token)})
                continue
            except Exception as e:
                pass

        try:
            mem_address, _ = Parser.parse_org(token)
            # это директива организации кода / данных в памяти
            # следующий байт-код будет иметь этот адрес
            mem_address, base = str_to_number(mem_address)
            code.append({"mem_address": mem_address, "is_org": True, "term": Term(line_num, token)})
            continue
        except Exception as e:
            pass

        try:
            # это размещение данных в памяти?
            label, directive, args = Parser.parse_data_def(token)

            label, last_root_label = check_new_label(label, last_root_label)

            max_uint = DataTypeDirective.get_max_uint(directive)

            # соберем информацию для корректного размещения `byte` и `word` в памяти
            data = []
            for i, arg in enumerate(args):
                if arg[0] == arg[-1] == "'":
                    # строчка
                    for char in arg[1:-1]:
                        data.append(data_dict(DataTypeDirective.BYTE, ord(char)))
                elif Parser.is_number(arg):
                    # число `byte` или `word`
                    number, base = str_to_number(arg)

                    if number > max_uint:
                        number = number & max_uint

                    # обрежем числа в аргументах
                    args[i] = ("-" if arg[0] == "-" else "") + (hex(number) if base == 16 else str(number))

                    if arg[0] == "-":
                        number = max_uint + 1 - number

                    data.append(data_dict(directive, number))
                else:
                    # метка, потом заменим
                    data.append(data_dict(DataTypeDirective.WORD, arg))

            mnemonic = "" if label is None else (label + ": ")
            mnemonic += directive + " "
            mnemonic += ", ".join(args)

            code.append({"mem_address": 0, "is_data": True, "label": label, "data": data, "term": Term(line_num, mnemonic.strip(" "))})
            continue
        except Exception as e:
            # не размещение данных
            pass

        try:
            # это инструкция?
            label, directive, instruction, args = Parser.parse_instruction(token)

            label, last_root_label = check_new_label(label, last_root_label)

            # почти полностью кодируем инструкцию в машинный код
            # кодирование не касается указателей, так как мы пока не знаем где они размещены
            # со всем остальным - всё хорошо

            data = []

            if directive == DataTypeDirective.BYTE:
                data.append(data_dict(DataTypeDirective.BYTE, InstructionPrefix.BYTE))

            max_uint = DataTypeDirective.get_max_uint(directive)

            op = Parser.symbol_to_opcode(instruction)
            data.append(data_dict(DataTypeDirective.BYTE, op))

            if op_has_no_args(op):
                pass
            elif op_has_1_arg(op):
                # инструкция требует 1 аргумент

                if len(args) != 1:
                    raise Exception("Инструкция {} требует ровно 1 аргумент".format(instruction))

                arg = args[0]
                is_number, is_register, is_label, is_memory = arg_is_number_register_label_or_memory(arg)
                if op1_arg_for_w(op) and (is_number or is_label):
                    raise Exception(
                        "Инструкция {} требует аргумент для записи (регистр или память)".format(instruction))

                byte_code, args[0] = encode_instruction_arg(directive, arg)
                data.extend(byte_code)

            elif op_has_2_args(op):
                # инструкция требует 2 аргумента

                if len(args) != 2:
                    raise Exception("Инструкция {} требует ровно 2 аргумента".format(instruction))

                arg1_is_number, arg1_is_register, arg1_is_label, arg1_is_memory = arg_is_number_register_label_or_memory(args[0])
                if arg1_is_number or arg1_is_label:
                    raise Exception("Инструкция {} требует первый аргумент для записи (регистр или память)".format(instruction))

                byte_code, args[0] = encode_instruction_arg(directive, args[0])
                data.extend(byte_code)

                byte_code, args[1] = encode_instruction_arg(directive, args[1])
                data.extend(byte_code)
            else:
                # инструкция требует N (1 байт) аргументов

                data.extend(ByteCodeFile.number_to_big_endian(len(args), DataTypeDirective.get_bytes_count(DataTypeDirective.BYTE)))

                arg1_is_number, arg1_is_register, arg1_is_label, arg1_is_memory = arg_is_number_register_label_or_memory(args[0])
                if arg1_is_number or arg1_is_label:
                    raise Exception("Инструкция {} требует первый аргумент для записи (регистр или память)".format(instruction))

                byte_code, args[0] = encode_instruction_arg(directive, args[0])
                data.extend(byte_code)

                for key in range(1, len(args)):
                    byte_code, args[key] = encode_instruction_arg(directive, args[key])
                    data.extend(byte_code)

            mnemonic = "" if label is None else (label + ": ")
            mnemonic += instruction + " "
            mnemonic += "" if (directive is None) or (directive == "word") else (directive + " ")
            mnemonic += ", ".join(args)

            code.append({"mem_address": 0, "is_instruction": True, "label": label, "data": data, "term": Term(line_num, mnemonic.strip(" "))})
            continue
        except Exception as e:
            # не инструкция xD
            pass

        raise Exception("`{}` - не пойми че написано, вот как можно:"
                        "\nОрганизация памяти = org (number)"
                        "\nТолько метка = label:"
                        "\nОпределить данные = (label:)? (byte|word) data (, data)*"
                        "\nЗаписать инструкцию = (label:)? op (byte|word)? operand (, (byte|word)? operand)*".format(token))

    if entry_point_label not in labels:
        raise Exception("В коде должна присутствовать метка `{}`, откуда начнется исполнение программы".format(entry_point_label))

    return labels, code


def translate_stage_2(labels, code):
    """
    Второй проход транслятора.

    Происходит подсчет адресов для меток, инструкций и кода, на основе директивы `org`
    """

    # Первый свободный адрес, откуда по-умолчанию транслятор начинает пихать данные и код
    mem_address = 0x0020
    organize_address = 0
    organize_next = False

    labels_waiting_to_init = []

    for line in code:
        if organize_next:
            mem_address = organize_address
            organize_next = False

        if "is_org" in line:
            organize_address = line["mem_address"]
            organize_next = True
        elif ("is_data" in line) or ("is_instruction" in line):
            line["mem_address"] = mem_address

            aligned_data = []
            for i, piece in enumerate(line["data"]):
                if piece["type"] == DataTypeDirective.BYTE:
                    aligned_data.append(piece["value"])
                    mem_address += 1
                else:
                    # для `word` надо делать ВЫРАВНИВАНИЕ (пусть будет...)
                    if mem_address & 0x0001 == 1:
                        aligned_data.append(0)
                        mem_address += 1
                        # print("Выравнивание `word` на {}".format(hex(mem_address)))

                    if i == 0:
                        line["mem_address"] = mem_address

                    if Parser.is_label_name(piece["value"]):
                        aligned_data.append(piece["value"])
                    else:
                        aligned_data.extend(ByteCodeFile.number_to_big_endian(piece["value"], DataTypeDirective.get_bytes_count(piece["type"])))

                    mem_address += 2

            line["data"] = aligned_data

            if (line["label"] is not None) and (labels[line["label"]] < 0):
                labels_waiting_to_init.append(line["label"])

            for label in labels_waiting_to_init:
                labels[label] = line["mem_address"]
                labels_waiting_to_init = []
        elif "label" in line:
            # только метка
            labels_waiting_to_init.append(line["label"])
        else:
            raise Exception("Чето не то в словарях кода")

    return labels, code


def translate_stage_3(labels, code):
    """
    Третий проход транслятора.

    Пихаем адреса меток
    """

    new_code = []
    for line in code:
        if "data" in line:
            for i, piece in enumerate(line["data"]):
                if isinstance(piece, str):
                    if (piece not in labels) or (labels[piece] < 0):
                        raise Exception("Метка `{}` - не определена".format(piece))

                    line["data"] = line["data"][:i] + ByteCodeFile.number_to_big_endian(labels[piece], DataTypeDirective.get_bytes_count(DataTypeDirective.WORD)) + line["data"][i + 1:]

            new_code.append({"mem_address": line["mem_address"], "byte_code": line["data"], "term": line["term"]})

    new_code.sort(key=lambda v: v["mem_address"])

    return new_code


def translate_stage_4(code):
    """
    Четвертый проход транслятора.

    Проверяем, не перекрывают ли данные друг друга
    """

    last_used_address = -1
    for i, line in enumerate(code):
        address = line["mem_address"]
        if address <= last_used_address:
            raise Exception("Данные/код перекрыли друг друга: \n{}\n{}".format(code[i - 1], line))
        last_used_address = address + len(line["byte_code"]) - 1

    return code


def translate(text):
    """Трансляция текста программы на Asm в машинный код.

    Выполняется в 4 прохода:

    1. Разбор текста на метки и инструкции.

    2. Организация данных/кода, расчет адресов меток

    3. Подстановка адресов меток в операнды инструкции.

    4. Проверка перекрытия данных/кода друг друга
    """
    labels, code = translate_stage_1(text)
    labels, code = translate_stage_2(labels, code)
    code = translate_stage_3(labels, code)
    code = translate_stage_4(code)

    print("\n".join([str(line) for line in code]))

    return code


def main(source, target):
    """Функция запуска транслятора. Параметры -- исходный и целевой файлы."""
    with open(source, encoding="utf-8") as f:
        source = f.read().lower()

    code = translate(source)

    ByteCodeFile.write(target, code)
    ByteCodeFile.write_debug(target + ".debug", code)

    print("source LoC:", len(source.split("\n")), "asm instr:", len(code))


if __name__ == "__main__":
    # assert len(sys.argv) == 3, "Wrong arguments: translator_asm.py <input_file> <target_file>"
    _, source, target = sys.argv, "./example/simple.txt", "./target/simple.o"
    main(source, target)

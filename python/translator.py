#!/usr/bin/python3
import isa
import re
import sys
import typing


def data_dict(datatype, value):
    return {"type": datatype, "value": value}


def str_to_number(number):
    neg = number[0] == "-"
    if neg:
        number = number[1:]

    try:
        if (len(number) > 2) and (number[:2] == "0x"):
            value, base = int(number, 16), 16
        else:
            value, base = int(number), 10
    except ValueError as e:
        raise ValueError("Не число: {}".format(number)) from e

    return value, base


def str_to_hex(string, directive):
    string = string.strip("'")

    repeats = 1
    if directive == isa.DataTypeDirectives.WORD:
        repeats = 2
    elif directive == isa.DataTypeDirectives.DWORD:
        repeats = 4

    result = [ord(char) for char in string]
    n = len(result)
    if n < repeats:
        result = [0] * (n - repeats) + result

    result = [result[i] << ((repeats - i - 1) * 8) for i in range(repeats)]
    return hex(sum(result))


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

    org_directive: typing.ClassVar[str] = isa.OrgDirective.ORG
    type_directives_names: typing.ClassVar[list] = list(isa.DataTypeDirectives.directive_by_name.keys())
    number_regex: typing.ClassVar[typing.Pattern[typing.AnyStr]] = re.compile(r"([\-+]?(0x[\da-f]+|\d+))")
    string_regex: typing.ClassVar[typing.Pattern[typing.AnyStr]] = re.compile(r"(\'[^\']+\')")
    label_name_regex: typing.ClassVar[typing.Pattern[typing.AnyStr]] = re.compile(r"([_.a-z][_.\da-z]*)")
    org_directive_regex: typing.ClassVar[typing.Pattern[typing.AnyStr]] = re.compile(r"org\s*(0x[\da-f]+|\d+)")
    general_purpose_registers: typing.ClassVar[dict] = {
        value.name for value in isa.Registers.code_to_general_register_dict.values()
    }

    mnemonic_to_instruction_dict: typing.ClassVar[dict] = isa.InstructionSet.mnemonic_to_instruction_dict

    opcode_to_mnemonic_dict: typing.ClassVar[dict] = {
        value.opcode: value.mnemonic for value in mnemonic_to_instruction_dict.values()
    }

    key_words: typing.ClassVar[set] = set(list(mnemonic_to_instruction_dict.keys()) +
                                          list(org_directive) + list(type_directives_names))

    class Exceptions:
        class LabelError(Exception):
            def __init__(self, msg):
                super().__init__(msg)

        class LocalLabelNameError(LabelError):
            def __init__(self, msg):
                super().__init__("Две `.` в имени метки подряд запрещены: {}".format(msg))

        class LabelNameError(LabelError):
            def __init__(self, msg):
                super().__init__("Метка так не пишется: {}".format(msg))

        class LabelWithoutColonError(LabelError):
            def __init__(self, msg):
                super().__init__("Ожидается `:` после имени метки: {}".format(msg))

        class DataTypeDirectiveError(Exception):
            def __init__(self, msg):
                super().__init__(msg)

        class DataTypeDirectiveNoSpaceError(DataTypeDirectiveError):
            def __init__(self, msg):
                super().__init__("После имени директивы типа данных ожидался пробел: {}".format(msg))

        class NoSuchDataTypeDirectiveNameError(DataTypeDirectiveError):
            def __init__(self, msg):
                super().__init__("Нет такого имени директивы типа данных: {}".format(msg))

        class OrgDirectiveError(Exception):
            def __init__(self, msg):
                super().__init__(msg)

        class OrgDirectivePatternError(OrgDirectiveError):
            def __init__(self, msg):
                super().__init__("Неправильная запись директивы `org` размещения данных: {}".format(msg))

        class NumberError(Exception):
            def __init__(self, msg):
                super().__init__(msg)

        class NumberPatternError(NumberError):
            def __init__(self, msg):
                super().__init__("Не совпадает с паттерном числа-литерала: {}".format(msg))

        class StringError(Exception):
            def __init__(self, msg):
                super().__init__(msg)

        class StringPatternError(StringError):
            def __init__(self, msg):
                super().__init__("Не совпадает с паттерном строки-литерала: {}".format(msg))

        class DupError(Exception):
            def __init__(self, msg):
                super().__init__(msg)

        class DupRepeatCountError(DupError):
            def __init__(self, msg):
                super().__init__("Перед `dup` ожидалось число повторений: {}".format(msg))

        class DupKeyWordError(DupError):
            def __init__(self, msg):
                super().__init__("После числа повторений ожидалось `dup`: {}".format(msg))

        class DupLeftBracketError(DupError):
            def __init__(self, msg):
                super().__init__("Аругменты `dup` должны идти после скобки `(`: {}".format(msg))

        class DupRightBracketError(DupError):
            def __init__(self, msg):
                super().__init__("Аругменты `dup` должны идти после скобки `(`: {}".format(msg))

        class DataDefinitionError(Exception):
            def __init__(self, msg):
                super().__init__(msg)

        class DataDefinitionNoArgsError(DataDefinitionError):
            def __init__(self, msg):
                super().__init__("После директивы ожидались данные: {}".format(msg))

        class InstructionArgsError(Exception):
            def __init__(self, msg):
                super().__init__(msg)

        class InstructionNoArgsError(InstructionArgsError):
            def __init__(self, msg):
                super().__init__("После инструкции ожидались аргументы: {}".format(msg))

        class MnemonicError(Exception):
            def __init__(self, msg):
                super().__init__(msg)

        class MnemonicNameError(MnemonicError):
            def __init__(self, msg):
                super().__init__("`{}` не мнемоника инструкции".format(msg))

        class RegisterError(Exception):
            def __init__(self, msg):
                super().__init__(msg)

        class RegisterNameError(RegisterError):
            def __init__(self, msg):
                super().__init__("Ожидался регистр, регистры общего назначения = {}".format(msg))

        class MemoryAddressingError(Exception):
            def __init__(self, msg):
                super().__init__(msg)

        class MemoryAddressingLeftBracketError(MemoryAddressingError):
            def __init__(self, msg):
                super().__init__("Адресация памяти начинается с `[`: {}".format(msg))

        class MemoryAddressingRightBracketError(MemoryAddressingError):
            def __init__(self, msg):
                super().__init__("Адресация памяти заканчивается на `]`: {}".format(msg))

        class AddressBaseError(MemoryAddressingError):
            def __init__(self, msg):
                super().__init__("Ожидалась основа адреса: {}".format(msg))

        class ScaleSignError(MemoryAddressingError):
            def __init__(self, msg):
                super().__init__("После индекса ожидается знак и число `*scale`: {}".format(msg))

        class ScaleFactorError(MemoryAddressingError):
            def __init__(self, msg):
                super().__init__("Плохой `scale factor`: {}".format(msg))

        class AddressOffsetError(MemoryAddressingError):
            def __init__(self, msg):
                super().__init__("Ожидалось смещение адреса (число, регистр): {}".format(msg))

    @staticmethod
    def is_string(string):
        if not isinstance(string, str):
            return False

        match = Parser.string_regex.match(string)

        if match is None:
            return False

        return match.string == string

    @staticmethod
    def is_number(string):
        if not isinstance(string, str):
            return False

        match = Parser.number_regex.match(string)

        if match is None:
            return False

        return match.string == string

    @staticmethod
    def is_hex(string):
        return Parser.is_number(string) and string[:2] == "0x"

    @staticmethod
    def is_dec(string):
        return Parser.is_number(string) and string[:2] != "0x"

    @staticmethod
    def is_label_name(string):
        string = str(string)

        match = Parser.label_name_regex.match(string)

        if match is None:
            return False

        return match.string == string

    @staticmethod
    def mnemonic_to_instruction(mnemonic: str):
        return Parser.mnemonic_to_instruction_dict.get(mnemonic)

    @staticmethod
    def opcode_to_mnemonic(opcode: int):
        return Parser.opcode_to_mnemonic_dict.get(opcode)

    @staticmethod
    def try_find_label_name(line: str):
        match = Parser.label_name_regex.match(line)

        if match is None:
            raise Parser.Exceptions.LabelNameError(line)

        label_name = match.group(1)
        if label_name.find("..") >= 0:
            raise Parser.Exceptions.LocalLabelNameError(label_name)

        return label_name, line[match.end(1):].lstrip(" ")

    @staticmethod
    def parser_label_with_colon(line: str, add_colon=False):
        label_name, line = Parser.try_find_label_name(line)

        if len(line) == 0 or line[0] != ":":
            raise Parser.Exceptions.LabelWithoutColonError(label_name + line)

        return label_name + (":" if add_colon else ""), line[1:].lstrip(" ")

    @staticmethod
    def try_find_type_directive_name(line: str):
        line = line.lstrip(" ")

        pos = line.find(" ")

        if pos < 0:
            raise Parser.Exceptions.DataTypeDirectiveNoSpaceError(line)

        directive_name = line[:pos]

        if directive_name not in Parser.type_directives_names:
            raise Parser.Exceptions.NoSuchDataTypeDirectiveNameError(directive_name)

        return directive_name, line[pos:].lstrip(" ")

    @staticmethod
    def try_find_number(line: str):
        """
        :raise Parser.NotNumberException:
        """
        line = line.lstrip(" ")

        match = Parser.number_regex.match(line)

        if match is None:
            raise Parser.Exceptions.NumberPatternError(line)

        return match.group(1).lstrip("+"), line[match.end(1):].lstrip(" ")

    @staticmethod
    def try_find_string(line: str):
        line = line.lstrip(" ")

        match = Parser.string_regex.match(line)

        if match is None:
            raise Parser.Exceptions.StringPatternError(line)

        return match.group(1), line[match.end(1):].lstrip(" ")

    @staticmethod
    def try_find_dup(line: str):
        try:
            number, line = Parser.try_find_number(line)
        except Parser.Exceptions.NumberError as e:
            raise Parser.Exceptions.DupRepeatCountError(line) from e

        pos = 3
        if line[:pos] != "dup":
            raise Parser.Exceptions.DupKeyWordError(line)

        line = line[pos:].lstrip(" ")

        if line[0] != "(":
            raise Parser.Exceptions.DupLeftBracketError(line)

        line = line[1:].lstrip(" ")

        args, line = Parser.try_find_data_args(line)
        line = line.lstrip(" ")

        if line[0] != ")":
            raise Parser.Exceptions.DupRightBracketError(line)

        if number.find("0x") >= 0:
            number = int(number, 16)
        else:
            number = int(number)

        return args * number, line[1:].lstrip(" ")

    @staticmethod
    def try_find_data_args(line: str):
        args = []
        found_one = False

        try:
            dup, line = Parser.try_find_dup(line)
            args.extend(dup)
            found_one = True
        except Parser.Exceptions.DupError:
            pass

        try:
            label_name, line = Parser.try_find_label_name(line)
            args.append(label_name)
            found_one = True
        except Parser.Exceptions.LabelError:
            pass

        try:
            number, line = Parser.try_find_number(line)
            args.append(number)
            found_one = True
        except Parser.Exceptions.NumberError:
            pass

        try:
            string, line = Parser.try_find_string(line)
            args.append(string)
            found_one = True
        except Parser.Exceptions.StringError:
            pass

        if not found_one:
            raise Parser.Exceptions.DataDefinitionNoArgsError(line)

        if len(line) > 0 and line[0] == ",":
            new_args, line = Parser.try_find_data_args(line[1:].lstrip(" "))
            args.extend(new_args)

        return args, line

    @staticmethod
    def try_find_mnemonic(line: str):
        pos = line.find(" ")
        if pos < 0:
            pos = len(line)

        mnemonic = line[:pos].lower()

        if mnemonic not in Parser.mnemonic_to_instruction_dict:
            raise Parser.Exceptions.MnemonicNameError(mnemonic)

        return mnemonic, line[pos:].lstrip(" ")

    @staticmethod
    def try_find_instruction_args(line: str):
        args = []
        found = False

        try:
            directive_name, line = Parser.try_find_type_directive_name(line)
            args.append(directive_name)
        except Parser.Exceptions.DataTypeDirectiveError:
            pass

        try:
            base, index_sign, index, scale_factor, offset_sign, offset, line = Parser.try_find_memory_addressing(line)
            args.append({
                "base": base,
                "index_sign": index_sign,
                "index": index,
                "scale_factor": scale_factor,
                "offset_sign": offset_sign,
                "offset": offset
            })
            found = True
        except Parser.Exceptions.MemoryAddressingError:
            pass

        try:
            reg, line = Parser.try_find_register(line)
            args.append(reg)
            found = True
        except Parser.Exceptions.RegisterError:
            pass

        try:
            label_name, line = Parser.try_find_label_name(line)
            args.append(label_name)
            found = True
        except Parser.Exceptions.LabelError:
            pass

        try:
            number, line = Parser.try_find_number(line)
            args.append(number)
            found = True
        except Parser.Exceptions.NumberError:
            pass

        try:
            string, line = Parser.try_find_string(line)
            args.append(string)
            found = True
        except Parser.Exceptions.StringError:
            pass

        if not found:
            raise Parser.Exceptions.InstructionNoArgsError(line)

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

        raise Parser.Exceptions.RegisterNameError(line)

    @staticmethod
    def try_find_address_base(line: str):
        line_copy = line[:]

        try:
            number, line = Parser.try_find_number(line)
        except Parser.Exceptions.NumberError:
            pass
        else:
            return number, line

        try:
            reg, line = Parser.try_find_register(line)
        except Parser.Exceptions.RegisterError:
            pass
        else:
            return reg, line

        try:
            label, line = Parser.try_find_label_name(line)
        except Parser.Exceptions.LabelError:
            pass
        else:
            return label, line

        raise Parser.Exceptions.AddressBaseError(line_copy)

    @staticmethod
    def try_find_addressing_sign(line: str):
        if (line[0] == "-") or (line[0] == "+"):
            return line[0], line[1:].lstrip(" ")

        return "+", line

    @staticmethod
    def try_find_scale_sign(line: str):
        if line[0] == "*":
            return line[0], line[1:].lstrip(" ")

        raise Parser.Exceptions.ScaleSignError(line)

    @staticmethod
    def try_find_array_index(line: str):
        sign, line = Parser.try_find_addressing_sign(line)
        index, line = Parser.try_find_register(line)
        _, line = Parser.try_find_scale_sign(line)
        scale_factor, line = Parser.try_find_number(line)

        number = int(scale_factor)
        if number not in isa.InstructionPostfix.valid_scale_factors:
            raise Parser.Exceptions.ScaleFactorError(line)

        return sign, index, scale_factor, line

    @staticmethod
    def try_find_address_offset(line: str):
        line_copy = line[:]
        sign, line = Parser.try_find_addressing_sign(line)

        try:
            number, line = Parser.try_find_number(line)
        except Parser.Exceptions.NumberError:
            pass
        else:
            return sign, number, line

        try:
            reg, line = Parser.try_find_register(line)
        except Parser.Exceptions.RegisterError:
            pass
        else:
            return sign, reg, line

        raise Parser.Exceptions.AddressOffsetError(line_copy)

    @staticmethod
    def try_find_memory_addressing(line):
        line_copy = line[:]
        if line[0] != "[":
            raise Parser.Exceptions.MemoryAddressingLeftBracketError(line_copy)

        line = line[1:].lstrip(" ")

        base, line = Parser.try_find_address_base(line)

        try:
            index_sign, index, scale_factor, line = Parser.try_find_array_index(line)
        except Parser.Exceptions.ScaleFactorError:
            index_sign, index, scale_factor = None, None, None

        try:
            offset_sign, offset, line = Parser.try_find_address_offset(line)
        except Parser.Exceptions.AddressOffsetError:
            offset_sign, offset = None, None

        if line[0] != "]":
            raise Parser.Exceptions.MemoryAddressingRightBracketError(line_copy)

        return base, index_sign, index, scale_factor, offset_sign, offset, line[1:].strip(" ")

    @staticmethod
    def parse_org(line: str):
        match = Parser.org_directive_regex.match(line)

        if match is None:
            raise Parser.Exceptions.OrgDirectivePatternError(line)

        return match.group(1), line[match.end(1):]

    @staticmethod
    def parse_data_def(line: str):
        try:
            label, line = Parser.parser_label_with_colon(line)
        except Parser.Exceptions.LabelError:
            label = None

        directive_name, line = Parser.try_find_type_directive_name(line)
        args, line = Parser.try_find_data_args(line)

        return label, directive_name, args

    @staticmethod
    def parse_instruction(line: str):
        try:
            label, line = Parser.parser_label_with_colon(line)
        except Parser.Exceptions.LabelError:
            label = None

        directive_name = isa.DataTypeDirectives.WORD.name
        mnemonic, line = Parser.try_find_mnemonic(line)

        args = []
        try:
            args, line = Parser.try_find_instruction_args(line)
        except Parser.Exceptions.InstructionArgsError:
            pass

        for type_dir in Parser.type_directives_names:
            if type_dir in args:
                # если есть хоть одна директива начиная с `byte` и далее,
                # то все операнды вынуждены приводиться к ней (самой меньшей)
                # или например если меньшая директива = `word`...
                args = [arg for arg in args if arg not in Parser.type_directives_names]
                directive_name = type_dir

        return label, directive_name, mnemonic, args


def arg_is_number_register_label_or_addressing(arg):
    is_addressing = isinstance(arg, dict)

    if is_addressing:
        return False, False, False, is_addressing

    is_number = Parser.is_number(arg)
    is_register = arg in Parser.general_purpose_registers
    is_label = (not is_register) and Parser.is_label_name(arg)

    return is_number, is_register, is_label, is_addressing


def encode_instruction_arg(directive_name, arg):
    max_uint = isa.DataTypeDirectives.get_directive_by_name(directive_name).max_uint
    data = []

    is_number, is_register, is_label, is_memory = arg_is_number_register_label_or_addressing(arg)

    if is_label:
        data.append(data_dict(isa.DataTypeDirectives.BYTE.name, isa.InstructionPostfix.ArgIsImmediate))
        data.append(data_dict(isa.DataTypeDirectives.WORD.name, arg))
    elif is_number:
        data.append(data_dict(isa.DataTypeDirectives.BYTE.name, isa.InstructionPostfix.ArgIsImmediate))

        number, base = str_to_number(arg)
        if number > max_uint:
            number = number & max_uint

        arg = ("-" if arg[0] == "-" else "") + (hex(number) if base == 16 else str(number))

        if arg[0] == "-":
            number = max_uint + 1 - number

        data.append(data_dict(directive_name, number))
    elif is_register:
        data.append(data_dict(isa.DataTypeDirectives.BYTE.name, isa.InstructionPostfix.encode_register(arg)))
    else:
        has_offset = arg["offset"] is not None
        has_index = arg["index"] is not None
        scale_factor = (arg["scale_factor"] is not None)
        offset_sign = (arg["offset_sign"] is not None) and (arg["offset_sign"] == "-")
        index_sign = (arg["index_sign"] is not None) and (arg["index_sign"] == "-")

        data.append(data_dict(
            isa.DataTypeDirectives.BYTE.name,
            isa.InstructionPostfix.encode_addressing_mode(
                has_offset, has_index, scale_factor, offset_sign, index_sign
            )
        ))

        byte_code, arg["base"] = encode_instruction_arg(isa.DataTypeDirectives.WORD.name, arg["base"])
        data.extend(byte_code)

        if has_index:
            byte_code, arg["index"] = encode_instruction_arg(isa.DataTypeDirectives.WORD.name, arg["index"])
            data.extend(byte_code)

        if has_offset:
            byte_code, arg["offset"] = encode_instruction_arg(isa.DataTypeDirectives.WORD.name, arg["offset"])
            data.extend(byte_code)

        arg_str = arg["base"]
        if has_index:
            arg_str += ("-" if index_sign else "+") + arg["index"] + "*" + arg["scale_factor"]

        if has_offset:
            arg_str += ("-" if offset_sign else "+") + arg["offset"]

        arg = "[" + arg_str + "]"

    return data, arg


class Translator:
    entry_point_label = "start"

    class Exceptions:
        class LabelError(Exception):
            def __init__(self, msg):
                super().__init__(msg)

        class LabelColonError(LabelError):
            def __init__(self, msg):
                super().__init__("Только один символ `:` должен быть после имени метки: {}".format(msg))

        class LabelKeyWordError(LabelError):
            def __init__(self, msg):
                super().__init__("Нельзя назначить метку `{}` с именем ключевого слова".format(msg))

        class LabelRedefinitionError(LabelError):
            def __init__(self, msg):
                super().__init__("Переопределение метки: {}".format(msg))

        class LabelNotDefinedError(LabelError):
            def __init__(self, msg):
                super().__init__("Метка `{}` - не определена".format(msg))

        class InstructionError(Exception):
            def __init__(self, msg):
                super().__init__(msg)

        class InstructionArgsError(InstructionError):
            def __init__(self, instruction):
                super().__init__(
                    "Инструкция `{}` принимает аргументы следующих типов: {}"
                    .format(
                        instruction.mnemonic,
                        isa.InstructionSet.form_args_types_str(
                            instruction.args_types,
                            instruction.variable_args_count
                        )
                    )
                )

        class InstructionArgsCountError(InstructionError):
            def __init__(self, count):
                super().__init__("{} - слишком много аргументов, максимум: {}".format(count, 0xFF))

        class InstructionValidationError(InstructionError):
            def __init__(self, msg):
                super().__init__("{}".format(msg))

        class UnknownStatementError(Exception):
            def __init__(self, msg):
                super().__init__(
                    "Не метка, не организация памяти, не определение данных и не инструкция: {}".format(msg)
                )

        class NoEntryPointError(Exception):
            def __init__(self, msg):
                super().__init__(
                    "В коде должна присутствовать метка `{}`, откуда начнется исполнение программы".format(msg)
                )

        class MemoryLayersCrossingError(Exception):
            def __init__(self, first, second):
                super().__init__("Данные/код перекрыли друг друга: \n{}\n{}".format(first, second))

    @staticmethod
    def stage_1(text, print_err):
        """
        Первый проход транслятора.
        Преобразование текста программы в список организации памяти, инструкций и размещений данных.
        """

        def check_new_label(new_label, root_label):
            if new_label is None or len(new_label) == 0:
                return new_label, root_label

            if new_label[0] == ".":
                # локальный для последнего глобального
                new_label = root_label + new_label
            else:
                root_label = new_label

            if new_label in Parser.key_words:
                raise Translator.Exceptions.LabelKeyWordError(new_label)

            if new_label in labels:
                raise Translator.Exceptions.LabelRedefinitionError(new_label)

            labels[new_label] = -1

            return new_label, root_label

        code = []
        labels = {}
        last_root_label = ""

        for line_num, token in enumerate(text.splitlines(), 1):
            token = token.strip(" ")

            if token == "":
                continue

            try:
                label, line = Parser.parser_label_with_colon(token)

                if len(line) > 0 and line[0] == ":":
                    raise Translator.Exceptions.LabelColonError(token)

                label, last_root_label = check_new_label(label, last_root_label)

                code.append({"mem_address": 0, "label": label, "term": isa.Term(line_num, token)})
                continue
            except Parser.Exceptions.LabelError as e:
                if print_err:
                    print("Ошибка при проверке метки: {}".format(e))

            try:
                mem_address, _ = Parser.parse_org(token.lower())
                # это директива организации кода / данных в памяти
                # следующий байт-код будет иметь этот адрес
                mem_address, base = str_to_number(mem_address)
                code.append({"mem_address": mem_address, "is_org": True, "term": isa.Term(line_num, token)})
                continue
            except Parser.Exceptions.OrgDirectivePatternError as e:
                if print_err:
                    print("Ошибка при проверке `org`: {}".format(e))

            try:
                # это размещение данных в памяти?
                label, directive_name, args = Parser.parse_data_def(token)
                directive = isa.DataTypeDirectives.get_directive_by_name(directive_name)

                label, last_root_label = check_new_label(label, last_root_label)

                max_uint = directive.max_uint

                # соберем информацию для корректного размещения `byte` и `word` в памяти
                data = []
                for i, arg in enumerate(args):
                    if arg[0] == arg[-1] == "'":
                        # строчка
                        for char in arg[1:-1]:
                            data.append(data_dict(isa.DataTypeDirectives.BYTE.name, ord(char)))
                    elif Parser.is_number(arg):
                        # число `byte` или `word`
                        number, base = str_to_number(arg)

                        if number > max_uint:
                            number = number & max_uint

                        # обрежем числа в аргументах
                        args[i] = ("-" if arg[0] == "-" else "") + (hex(number) if base == 16 else str(number))

                        if arg[0] == "-":
                            number = max_uint + 1 - number

                        data.append(data_dict(directive_name, number))
                    else:
                        # метка, потом заменим
                        data.append(data_dict(isa.DataTypeDirectives.WORD.name, arg))

                term_mnemonic = "" if label is None else (label + ": ")
                term_mnemonic += directive_name + " "
                term_mnemonic += ", ".join(args)

                code.append({"mem_address": 0, "is_data": True, "label": label, "data": data,
                             "term": isa.Term(line_num, term_mnemonic.strip(" "))})
                continue
            except Parser.Exceptions.DataDefinitionError as e:
                if print_err:
                    print("Ошибка при проверки размещения данных: {}".format(e))

            try:
                # это инструкция?
                label, directive_name, mnemonic, args = Parser.parse_instruction(token)
                directive = isa.DataTypeDirectives.get_directive_by_name(directive_name)
                instruction = Parser.mnemonic_to_instruction(mnemonic)

                label, last_root_label = check_new_label(label, last_root_label)

                # почти полностью кодируем инструкцию в машинный код
                # кодирование не касается указателей, так как мы пока не знаем где они размещены
                # со всем остальным - всё хорошо

                data = []

                if directive == isa.DataTypeDirectives.BYTE:
                    data.append(data_dict(isa.DataTypeDirectives.BYTE.name, isa.InstructionPrefix.BYTE))
                elif directive == isa.DataTypeDirectives.DWORD:
                    data.append(data_dict(isa.DataTypeDirectives.BYTE.name, isa.InstructionPrefix.DWORD))

                op = instruction.opcode
                data.append(data_dict(isa.DataTypeDirectives.BYTE.name, op))

                args_count = len(instruction.args_types)

                if instruction.variable_args_count:
                    # инструкция принимает переменное число аргументов
                    args_count = len(args)

                    if args_count > 0xFF:
                        raise Translator.Exceptions.InstructionArgsCountError(args_count)

                    data.extend(
                        isa.ByteCodeFile.number_to_big_endian(args_count, isa.DataTypeDirectives.BYTE.bytes_count)
                    )

                for i in range(args_count):
                    if Parser.is_string(args[i]):
                        args[i] = str_to_hex(args[i], directive)

                    arg_is_number, arg_is_register, arg_is_label, arg_is_addressing = \
                        arg_is_number_register_label_or_addressing(args[i])

                    arg_type = isa.InstructionSet.form_arg_type(arg_is_number, arg_is_label, arg_is_register)
                    type_list_idx = i

                    if type_list_idx >= len(instruction.args_types):
                        type_list_idx = len(instruction.args_types) - 1

                    if not isa.InstructionSet.check_type_is_valid(arg_type, instruction.args_types[type_list_idx]):
                        raise Translator.Exceptions.InstructionArgsError(instruction)

                    byte_code, args[i] = encode_instruction_arg(directive_name, args[i])
                    data.extend(byte_code)

                is_correct, error_msg = instruction.validate_directive_and_args(directive, args)
                if not is_correct:
                    raise Translator.Exceptions.InstructionValidationError(error_msg)

                term_mnemonic = "" if label is None else (label + ": ")
                term_mnemonic += mnemonic + " "
                term_mnemonic += \
                    "" if (directive_name is None) or (directive_name == "word") \
                    else (directive_name + " ")
                term_mnemonic += ", ".join(args)

                code.append({"mem_address": 0, "is_instruction": True, "label": label, "data": data,
                             "term": isa.Term(line_num, term_mnemonic.strip(" "))})
                continue
            except Translator.Exceptions.InstructionError as e:
                if print_err:
                    print("Ошибка при проверке инструкции: {}".format(e))

            raise Translator.Exceptions.UnknownStatementError(token)

        if Translator.entry_point_label not in labels:
            raise Translator.Exceptions.NoEntryPointError(Translator.entry_point_label)

        return labels, code

    @staticmethod
    def stage_2(labels, code):
        """
        Второй проход транслятора.

        Подсчет адресов для меток, инструкций и кода, на основе директивы `org`
        """

        # Первый свободный адрес, откуда по-умолчанию транслятор начинает пихать данные и код
        mem_address = 0x0014
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

                byte_code = []
                for piece in line["data"]:
                    if isinstance(piece, int):
                        # количество аргументов для инструкций с переменным числом аргументов
                        byte_code.append(piece)
                        mem_address += 1
                    elif Parser.is_label_name(piece["value"]):
                        byte_code.append(piece["value"])
                        mem_address += 2
                    else:
                        directive = isa.DataTypeDirectives.directive_by_name.get(piece["type"])
                        byte_code.extend(isa.ByteCodeFile.number_to_big_endian(piece["value"], directive.bytes_count))
                        mem_address += directive.bytes_count

                line["data"] = byte_code

                if (line["label"] is not None) and (labels[line["label"]] < 0):
                    labels_waiting_to_init.append(line["label"])

                for label in labels_waiting_to_init:
                    labels[label] = line["mem_address"]
                    labels_waiting_to_init = []
            elif "label" in line:
                # только метка
                labels_waiting_to_init.append(line["label"])

        return labels, code

    @staticmethod
    def stage_3(labels, code):
        """
        Третий проход транслятора.

        Пихаем адреса меток
        """

        new_code = []
        for line in code:
            if "data" in line:
                new_data = []
                for i, piece in enumerate(line["data"]):
                    if isinstance(piece, str):
                        if (piece not in labels) or (labels[piece] < 0):
                            raise Translator.Exceptions.LabelNotDefinedError(piece)

                        new_data.extend(isa.ByteCodeFile.number_to_big_endian(
                            labels[piece],
                            isa.DataTypeDirectives.WORD.bytes_count
                        ))
                    else:
                        new_data.append(line["data"][i])

                new_code.append({"mem_address": line["mem_address"], "byte_code": new_data, "term": line["term"]})

        new_code.sort(key=lambda v: v["mem_address"])

        return new_code

    @staticmethod
    def stage_4(code):
        """
        Четвертый проход транслятора.

        Проверяем, не перекрывают ли данные друг друга
        """

        last_used_address = -1
        for i, line in enumerate(code):
            address = line["mem_address"]
            if address <= last_used_address:
                raise Translator.Exceptions.MemoryLayersCrossingError(code[i - 1], line)
            last_used_address = address + len(line["byte_code"]) - 1

        return code

    @staticmethod
    def translate(text, print_err):
        """Трансляция текста программы на Asm в машинный код.

        Выполняется в 4 прохода:

        1. Разбор текста на метки и инструкции.

        2. Организация данных/кода, расчет адресов меток

        3. Подстановка адресов меток в операнды инструкции.

        4. Проверка перекрытия данных/кода друг друга
        """
        labels, code = Translator.stage_1(text, print_err)
        labels, code = Translator.stage_2(labels, code)
        code = Translator.stage_3(labels, code)
        code = Translator.stage_4(code)

        return labels[Translator.entry_point_label], code


def main(source, target, target_debug, print_err=False):
    """Функция запуска транслятора. Параметры -- исходный и целевой файлы."""
    with open(source, encoding="utf-8") as f:
        source = f.read()

    start_address, code = Translator.translate(source, print_err)

    isa.ByteCodeFile.write(target, start_address, code)
    isa.ByteCodeFile.write_debug(target_debug, start_address, code)


if __name__ == "__main__":
    assert len(sys.argv) == 4, "Wrong arguments: translator_asm.py <input_file> <target_file> <debug_file>"
    _, v1, v2, v3 = sys.argv
    main(v1, v2, v3)

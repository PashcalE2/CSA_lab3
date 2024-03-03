#!/usr/bin/python3
import re
import sys

import isa


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
    except ValueError:
        raise ValueError("Странное какое-то число: {}".format(number))

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

    org_directive = isa.OrgDirective.ORG
    type_directives_names = list(isa.DataTypeDirectives.directive_by_name.keys())
    number_regex = re.compile(r"([\-+]?(0x[\da-f]+|\d+))")
    string_regex = re.compile(r"(\'[^\']+\')")
    label_name_regex = re.compile(r"([_.a-z][_.\da-z]*)")
    org_directive_regex = re.compile(r"org\s*(0x[\da-f]+|\d+)")
    general_purpose_registers = {value.name for value in isa.Registers.code_to_general_register_dict.values()}

    mnemonic_to_instruction_dict = isa.InstructionSet.mnemonic_to_instruction_dict

    opcode_to_mnemonic_dict = {
        value.opcode: value.mnemonic for value in mnemonic_to_instruction_dict.values()
    }

    key_words = set(list(mnemonic_to_instruction_dict.keys()) + list(org_directive) + list(type_directives_names))

    class Exceptions:
        class NotLabel(Exception):
            def __init__(self, msg=""):
                super().__init__(msg)

        class NotDataTypeDirective(Exception):
            def __init__(self, msg=""):
                super().__init__(msg)

        class NotOrgDirective(Exception):
            def __init__(self, msg=""):
                super().__init__(msg)

        class NotNumber(Exception):
            def __init__(self, msg=""):
                super().__init__(msg)

        class NotString(Exception):
            def __init__(self, msg=""):
                super().__init__(msg)

        class NotDup(Exception):
            def __init__(self, msg=""):
                super().__init__(msg)

        class NotDataDefinition(Exception):
            def __init__(self, msg=""):
                super().__init__(msg)

        class NotInstructionArgs(Exception):
            def __init__(self, msg=""):
                super().__init__(msg)

        class NotMnemonic(Exception):
            def __init__(self, msg=""):
                super().__init__(msg)

        class NotRegister(Exception):
            def __init__(self, msg=""):
                super().__init__(msg)

        class NotAddressBase(Exception):
            def __init__(self, msg=""):
                super().__init__(msg)

        class NotScaleSign(Exception):
            def __init__(self, msg=""):
                super().__init__(msg)

        class NotAddressIndex(Exception):
            def __init__(self, msg=""):
                super().__init__(msg)

        class NotAddressOffset(Exception):
            def __init__(self, msg=""):
                super().__init__(msg)

        class NotMemoryAddressing(Exception):
            def __init__(self, msg=""):
                super().__init__(msg)

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
            raise Parser.Exceptions.NotLabel("`{}` - не метка".format(line))

        label_name = match.group(1)
        if label_name.find("..") >= 0:
            raise Parser.Exceptions.NotLabel("В имени метки не может идти две `.` подряд")

        return label_name, line[match.end(1):].lstrip(" ")

    @staticmethod
    def parser_label_with_colon(line: str, add_colon=False):
        label_name, line = Parser.try_find_label_name(line)

        if len(line) == 0 or line[0] != ":":
            raise Parser.Exceptions.NotLabel("Метка должна кончаться на `:`")

        return label_name + (":" if add_colon else ""), line[1:].lstrip(" ")

    @staticmethod
    def try_find_type_directive_name(line: str):
        line = line.lstrip(" ")

        pos = line.find(" ")

        if pos < 0:
            raise Parser.Exceptions.NotDataTypeDirective("После директивы данных ожидался пробел")

        directive_name = line[:pos]

        if directive_name not in Parser.type_directives_names:
            raise Parser.Exceptions.NotDataTypeDirective(
                "`{}` - не директива, можно так = {}".format(directive_name, Parser.type_directives_names))

        return directive_name, line[pos:].lstrip(" ")

    @staticmethod
    def try_find_number(line: str):
        """
        :raise Parser.NotNumberException:
        """
        line = line.lstrip(" ")

        match = Parser.number_regex.match(line)

        if match is None:
            raise Parser.Exceptions.NotNumber(
                "`{}` - не число, можно так = [0x0123456789ABCDEF, 0123456789]".format(line))

        return match.group(1).lstrip("+"), line[match.end(1):].lstrip(" ")

    @staticmethod
    def try_find_string(line: str):
        line = line.lstrip(" ")

        match = Parser.string_regex.match(line)

        if match is None:
            raise Parser.Exceptions.NotString("`{}` - не строка, можно так = r\"'[^\']+'\"".format(line))

        return match.group(1), line[match.end(1):].lstrip(" ")

    @staticmethod
    def try_find_dup(line: str):
        try:
            number, line = Parser.try_find_number(line)
        except Parser.Exceptions.NotNumber:
            raise Parser.Exceptions.NotDup("Перед `dup` ожидалось число")

        pos = 3
        dup = line[:pos]

        if dup != "dup":
            raise Parser.Exceptions.NotDup("После числа ожидалось `dup`")

        line = line[pos:].lstrip(" ")

        if line[0] != "(":
            raise Parser.Exceptions.NotDup("После dup ожидалось `(`")

        line = line[1:].lstrip(" ")

        args, line = Parser.try_find_data_args(line)
        line = line.lstrip(" ")

        if line[0] != ")":
            raise Parser.Exceptions.NotDup("После аргументов ожидалось `)`")

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
        except Parser.Exceptions.NotDup:
            pass

        try:
            label_name, line = Parser.try_find_label_name(line)
            args.append(label_name)
            found_one = True
        except Parser.Exceptions.NotLabel:
            pass

        try:
            number, line = Parser.try_find_number(line)
            args.append(number)
            found_one = True
        except Parser.Exceptions.NotNumber:
            pass

        try:
            string, line = Parser.try_find_string(line)
            args.append(string)
            found_one = True
        except Parser.Exceptions.NotString:
            pass

        if not found_one:
            raise Parser.Exceptions.NotDataDefinition("После директивы ожидались данные")

        if len(line) > 0:
            if line[0] == ",":
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
            raise Parser.Exceptions.NotMnemonic("`{}` не мнемоника инструкции".format(mnemonic))

        return mnemonic, line[pos:].lstrip(" ")

    @staticmethod
    def try_find_instruction_args(line: str):
        args = []
        found = False

        try:
            directive_name, line = Parser.try_find_type_directive_name(line)
            args.append(directive_name)
        except Parser.Exceptions.NotDataTypeDirective:
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
        except Parser.Exceptions.NotMemoryAddressing:
            pass

        try:
            reg, line = Parser.try_find_register(line)
            args.append(reg)
            found = True
        except Parser.Exceptions.NotRegister:
            pass

        try:
            label_name, line = Parser.try_find_label_name(line)
            args.append(label_name)
            found = True
        except Parser.Exceptions.NotLabel:
            pass

        try:
            number, line = Parser.try_find_number(line)
            args.append(number)
            found = True
        except Parser.Exceptions.NotNumber:
            pass

        try:
            string, line = Parser.try_find_string(line)
            args.append(string)
            found = True
        except Parser.Exceptions.NotString:
            pass

        if not found:
            raise Parser.Exceptions.NotInstructionArgs("После инструкции ожидались аргументы")

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

        raise Parser.Exceptions.NotRegister(
            "Ожидался регистр, регистры общего назначения = {}"
            .format(Parser.general_purpose_registers)
        )

    @staticmethod
    def try_find_address_base(line: str):
        try:
            number, line = Parser.try_find_number(line)
            return number, line
        except Parser.Exceptions.NotNumber:
            pass

        try:
            reg, line = Parser.try_find_register(line)
            return reg, line
        except Parser.Exceptions.NotRegister:
            pass

        try:
            label, line = Parser.try_find_label_name(line)
            return label, line
        except Parser.Exceptions.NotLabel:
            pass

        raise Parser.Exceptions.NotAddressBase("Ожидалось основание адреса (число, метка, регистр)")

    @staticmethod
    def try_find_addressing_sign(line: str):
        if (line[0] == "-") or (line[0] == "+"):
            return line[0], line[1:].lstrip(" ")

        return "+", line

    @staticmethod
    def try_find_scale_sign(line: str):
        if line[0] == "*":
            return line[0], line[1:].lstrip(" ")

        raise Parser.Exceptions.NotScaleSign("После индекса ожидается `* scale`")

    @staticmethod
    def try_find_array_index(line: str):
        sign, line = Parser.try_find_addressing_sign(line)
        index, line = Parser.try_find_register(line)
        _, line = Parser.try_find_scale_sign(line)
        scale_factor, line = Parser.try_find_number(line)

        number = int(scale_factor)
        if number not in isa.InstructionPostfix.valid_scale_factors:
            raise Parser.Exceptions.NotAddressIndex(
                "`{}` - плохой `scale factor`, можно: {}"
                .format(scale_factor, isa.InstructionPostfix.valid_scale_factors)
            )

        return sign, index, scale_factor, line

    @staticmethod
    def try_find_address_offset(line: str):
        sign, line = Parser.try_find_addressing_sign(line)

        try:
            number, line = Parser.try_find_number(line)
            return sign, number, line
        except Parser.Exceptions.NotNumber:
            pass

        try:
            reg, line = Parser.try_find_register(line)
            return sign, reg, line
        except Parser.Exceptions.NotRegister:
            pass

        raise Parser.Exceptions.NotAddressOffset("Ожидалось смещение адреса (число, регистр)")

    @staticmethod
    def try_find_memory_addressing(line):
        if line[0] != "[":
            raise Parser.Exceptions.NotMemoryAddressing("Адресация памяти начинается с `[`")

        line = line[1:].lstrip(" ")

        base, line = Parser.try_find_address_base(line)

        try:
            index_sign, index, scale_factor, line = Parser.try_find_array_index(line)
        except Parser.Exceptions.NotAddressIndex:
            index_sign, index, scale_factor = None, None, None

        try:
            offset_sign, offset, line = Parser.try_find_address_offset(line)
        except Parser.Exceptions.NotAddressOffset:
            offset_sign, offset = None, None

        if line[0] != "]":
            raise Parser.Exceptions.NotMemoryAddressing("Адресация памяти заканчивается на `]`")

        return base, index_sign, index, scale_factor, offset_sign, offset, line[1:].strip(" ")

    @staticmethod
    def parse_org(line: str):
        match = Parser.org_directive_regex.match(line)

        if match is None:
            raise Parser.Exceptions.NotOrgDirective("`{}` - не директива `org`".format(line))

        return match.group(1), line[match.end(1):]

    @staticmethod
    def parse_data_def(line: str):
        try:
            label, line = Parser.parser_label_with_colon(line)
        except Parser.Exceptions.NotLabel:
            label = None

        directive_name, line = Parser.try_find_type_directive_name(line)
        args, line = Parser.try_find_data_args(line)

        return label, directive_name, args

    @staticmethod
    def parse_instruction(line: str):
        try:
            label, line = Parser.parser_label_with_colon(line)
        except Parser.Exceptions.NotLabel:
            label = None

        directive_name = isa.DataTypeDirectives.WORD.name
        mnemonic, line = Parser.try_find_mnemonic(line)

        args = []
        try:
            args, line = Parser.try_find_instruction_args(line)
        except Parser.Exceptions.NotInstructionArgs:
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
        class BadLabelName(Exception):
            def __init__(self, msg=""):
                super().__init__(msg)

        class LabelRedefinition(Exception):
            def __init__(self, msg=""):
                super().__init__(msg)

        class BadInstructionArgs(Exception):
            def __init__(self, msg=""):
                super().__init__(msg)

        class UnknownStatement(Exception):
            def __init__(self, msg=""):
                super().__init__(msg)

        class NoEntryPoint(Exception):
            def __init__(self, msg=""):
                super().__init__(msg)

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
                raise Translator.Exceptions.BadLabelName(
                    "Нельзя назначить метку `{}` с именем ключевого слова"
                    .format(new_label)
                )

            if new_label in labels:
                raise Translator.Exceptions.LabelRedefinition("Переопределение метки: {}".format(new_label))

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
                    raise Translator.Exceptions.BadLabelName(
                        "`{}` - после метки должен быть только один символ `:`"
                        .format(token)
                    )

                label, last_root_label = check_new_label(label, last_root_label)

                code.append({"mem_address": 0, "label": label, "term": isa.Term(line_num, token)})
                # print("[{}] Полученная мнемоника: {}".format(line_num + 1, token))
                continue
            except (Translator.Exceptions.BadLabelName, Translator.Exceptions.LabelRedefinition) as e:
                raise e
            except Parser.Exceptions.NotLabel as e:
                if print_err:
                    print("Ошибка при проверке метки: {}".format(e))

            try:
                mem_address, _ = Parser.parse_org(token.lower())
                # это директива организации кода / данных в памяти
                # следующий байт-код будет иметь этот адрес
                mem_address, base = str_to_number(mem_address)
                code.append({"mem_address": mem_address, "is_org": True, "term": isa.Term(line_num, token)})
                # print("[{}] Полученная мнемоника: {}".format(line_num + 1, token))
                continue
            except Parser.Exceptions.NotOrgDirective as e:
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
                # print("[{}] Полученная мнемоника: {}".format(line_num + 1, term_mnemonic))
                continue
            except (Translator.Exceptions.BadLabelName, Translator.Exceptions.LabelRedefinition) as e:
                raise e
            except Parser.Exceptions.NotDataDefinition as e:
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
                        raise Exception("{} - слишком много аргументов, максимум: {}".format(args_count, 0xFF))

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
                        raise Translator.Exceptions.BadInstructionArgs(
                            "Инструкция `{}` принимает аргументы следующих типов: {}\n#{} аргумент `{}` имеет тип: {}"
                            .format(
                                mnemonic,
                                isa.InstructionSet.form_args_types_str(
                                    instruction.args_types,
                                    instruction.variable_args_count
                                ),
                                i + 1,
                                args[i],
                                isa.InstructionPostfix.arg_type_to_str[arg_type]
                            )
                        )

                    byte_code, args[i] = encode_instruction_arg(directive_name, args[i])
                    data.extend(byte_code)

                is_correct, error_msg = instruction.validate_directive_and_args(directive, args)
                if not is_correct:
                    raise Translator.Exceptions.BadInstructionArgs(error_msg)

                term_mnemonic = "" if label is None else (label + ": ")
                term_mnemonic += mnemonic + " "
                term_mnemonic += \
                    "" if (directive_name is None) or (directive_name == "word") \
                    else (directive_name + " ")
                term_mnemonic += ", ".join(args)

                code.append({"mem_address": 0, "is_instruction": True, "label": label, "data": data,
                             "term": isa.Term(line_num, term_mnemonic.strip(" "))})
                # print("[{}] Полученная мнемоника: {}".format(line_num + 1, term_mnemonic))
                continue
            except (Translator.Exceptions.BadLabelName, Translator.Exceptions.LabelRedefinition) as e:
                raise e
            except Translator.Exceptions.BadInstructionArgs as e:
                if print_err:
                    print("Ошибка при проверке инструкции: {}".format(e))

            raise Translator.Exceptions.UnknownStatement("Не понятно что написано")

        if Translator.entry_point_label not in labels:
            raise Translator.Exceptions.NoEntryPoint(
                "В коде должна присутствовать метка `{}`, откуда начнется исполнение программы"
                .format(Translator.entry_point_label)
            )

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
            else:
                raise Exception("Чето не то в словарях кода")

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
                            raise Exception("Метка `{}` - не определена".format(piece))

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
                raise Exception("Данные/код перекрыли друг друга: \n{}\n{}".format(code[i - 1], line))
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

    # print("Количество строк исходного кода: {}".format(len(source.split("\n"))))
    # print("Количество строк тела объектного файла: {}".format(len(code)))


if __name__ == "__main__":
    assert len(sys.argv) == 4, "Wrong arguments: translator_asm.py <input_file> <target_file> <debug_file>"
    _, v1, v2, v3 = sys.argv
    main(v1, v2, v3)

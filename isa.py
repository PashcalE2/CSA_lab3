"""Представление исходного и машинного кода.

- По варианту, представление машинного кода - бинарное (binary) => машинный код будет читаться / записываться в бинарных файлах.
- По варианту, ControlUnit - часть модели (hardwired) => я могу не задумываться над соответствием операций их уникальному коду, так как ControlUnit будет просто сравнивать их с каждым кодом по-отдельности.

"""

import json
from collections import namedtuple
from enum import Enum


class Opcode(int, Enum):
    """
    Opcode для инструкций. Всего 43 инструкции (можно закодировать с помощью 6 бит).
    Они шаблонно разделены по количеству используемых аргументов.

    Аргументы инструкций = [<destination>, <source1>, <source2>, ...]

    Инструкции без аргументов:

    0 | 0 | x | x | x | x | x | x

    Инструкции с 1 аргументом:

    1 | 0 | w | x | x | x | x | x

    бит w == 0 => из аргумента только читаем.

    бит w == 1 => из аргумента можем читать, но точно запишем

    Инструкции с 2 аргументами:

    0 | 1 | x | x | x | x | x | x

    В первый аргумент точно будем писать (может еще читать), из второго  - только читать

    Инструкции с N аргументами:

    1 | 1 | x | x | x | x | x | x

    В первый аргумент точно будем писать (может еще читать), из остальных - только читать
    """

    # Инструкции без аргументов (10)
    NOP = 0x00
    HALT = 0x01
    CLC = 0x02
    CMC = 0x03

    PUSHF = 0x04
    POPF = 0x05

    EI = 0x06
    DI = 0x07
    RET = 0x08
    IRET = 0x09

    # Инструкции с 1 аргументом (18)
    NOT = 0xA0
    NEG = 0xA1
    INC = 0xA2
    DEC = 0xA3
    SXTB = 0xA4
    SWAB = 0xA5

    JMP = 0x80
    JL = 0x81
    JLE = 0x82
    JE = 0x83
    JNE = 0x84
    JG = 0x85
    JGE = 0x86
    LOOP = 0x87

    PUSH = 0x88
    CALL = 0x89
    POP = 0xB0

    INT = 0x90

    # Инструкции с 2 аргументами (15)
    MOV = 0x40

    AND = 0x50
    OR = 0x51
    XOR = 0x52

    ADD = 0x60
    ADC = 0x61
    SUB = 0x62
    ROL = 0x63
    ROR = 0x64
    ASL = 0x65
    ASR = 0x66
    MUL = 0x67
    DIV = 0x68

    CMP = 0x70
    SWAP = 0x71

    # Инструкции с N аргументами (1)
    POLY = 0xC0


def op1_arg_for_w(op: int):
    return op & 0x20


def op_has_no_args(op: int):
    return op & 0xC0 == 0x00


def op_has_1_arg(op: int):
    return op & 0xC0 == 0x80


def op_has_2_args(op: int):
    return op & 0xC0 == 0x40


def op_has_n_args(op: int):
    return op & 0xC0 == 0xC0


class OrgDirective:
    ORG = "org"


class DataTypeDirective:
    BYTE = "byte"
    WORD = "word"

    bytes_count_dict = {
        BYTE: 1,
        WORD: 2
    }

    max_uint_dict = {
        BYTE: 0xFF,
        WORD: 0xFFFF
    }

    @staticmethod
    def get_max_uint(directive):
        return DataTypeDirective.max_uint_dict[directive]

    @staticmethod
    def get_bytes_count(directive):
        return DataTypeDirective.bytes_count_dict[directive]


class InstructionPrefix:
    """
    Каждой инструкции с аргументом можно приписать директиву.
    Она определяет, с каким типом данных мы работаем в этой инструкции - `byte` или `word`
    Для `word` префикс не нужен так как он
    """
    BYTE = 0xFF


class InstructionPostfix:
    """
    Так как архитектура - CISC, то нужно как-то закодировать не всегда определенное количество аргументов.
    После кода инструкции будет следовать постфикс количества аргументов.
    По условию вроде требовалось бесконечно много, так что буду использовать `vlq`.

    После количества аргументов, для каждого будет 1 или несколько байт которые его определяют.
    Нужно будет определить:

    - значение на месте (`word` или `byte`) ИЛИ
    - регистр общего назначения (их 6) ИЛИ
    - режим адресации памяти (`base`, `base+offset`, `base+index*scale`, `base+index*scale+offset`) -- `word` операнды!

    Соответственно, после байта `значение на месте` будет идти операнд (в зависимости от директивы инструкции)

    В байте `регистр` будет закодирован регистр

    В байте `режим` будет режим, по которому ясно сколько читать дальше.
    Среди последующих байтов будут либо опять постфикс байт `значение на месте` (и соответственно, значение), либо `регистр`
    """

    ArgIsImmediate = 0xFF
    """
    1 | 1 | 1 | 1 | 1 | 1 | 1 | 1
    """

    ArgIsRegister = 0x80
    """
    1 | 0 | 0 | 0 | 0 | x | x | x
    
    6 регистров можно закодировать последовательностью в 3 бит
    """

    ArgsAreMemoryAddressing = 0x40
    """
    0 | 1 | 0 | is | os | s | i | o
    
    4 вида адресации можно закодировать в 2 бит
    
    бит s == 0 => scale_factor = 2 ^ 0 = 1
    
    бит s == 1 => scale_factor = 2 ^ 1 = 2
    
    я не знаю зачем, но пусть будет:
    
    бит is == 0 => знак индекса "+"
    
    бит is == 1 => знак индекса "-" (предварительно взять доп. код)
    
    бит os == 0 => знак смещения "+"
    
    бит os == 1 => знак смещения "-" (предварительно взять доп. код)
    """

    OffsetAddressingFlag = 0x1
    IndexAddressingFlag = 0x2
    OffsetSignFlag = 0x8
    IndexSignFlag = 0x10

    @staticmethod
    def encode_register(register_name: str):
        return InstructionPostfix.ArgIsRegister | Registers.register_to_code(register_name)

    @staticmethod
    def decode_register(byte: int):
        return Registers.code_to_register(byte & 0x7)

    @staticmethod
    def encode_addressing_mode(has_offset: bool, has_index: bool, scale_factor_power: int, offset_sign: bool, index_sign:bool):
        byte = InstructionPostfix.ArgsAreMemoryAddressing
        if has_offset:
            byte = byte | InstructionPostfix.OffsetAddressingFlag

            if offset_sign:
                byte = byte | InstructionPostfix.OffsetSignFlag

        if has_index:
            byte = byte | InstructionPostfix.IndexAddressingFlag | ((scale_factor_power & 0x1) << 2)

            if index_sign:
                byte = byte | InstructionPostfix.IndexSignFlag

        return byte

    @staticmethod
    def decode_addressing_mode(byte: int):
        has_offset = byte & 0x1

        byte = byte >> 1
        has_index = byte & 0x1

        byte = byte >> 1
        scale_factor_power = byte & 0x1

        byte = byte >> 1
        offset_sign = byte & 0x1

        byte = byte >> 1
        index_sign = byte & 0x1

        return has_offset, has_index, scale_factor_power, offset_sign, index_sign

    @staticmethod
    def get_scale_factor_max_pow():
        return 1


class Registers:
    """
    Что-то про регистры
    """

    AX = "ax"
    BX = "bx"
    CX = "cx"
    SP = "sp"
    DX = "dx"
    IP = "ip"
    PS = "ps"

    code_to_register_list = [AX, BX, CX, SP, DX, IP, PS]
    register_to_code_dict = {value: key for key, value in enumerate(code_to_register_list)}

    @staticmethod
    def code_to_register(code: int):
        return Registers.code_to_register_list[code]

    @staticmethod
    def register_to_code(reg: str):
        return Registers.register_to_code_dict.get(reg)


class Term(namedtuple("Term", "line mnemonic")):
    """Описание выражения из исходного текста программы.

    Сделано через класс, чтобы был docstring.
    """


class ByteCodeFile:
    """
    Структура файла такая:

    - 'уникальный' заголовок
    - <2 байта на количество инструкций>
    - <2 байта на адрес> <2 байта на длину инструкции> <инструкция>
    - <2 байта на адрес> <2 байта на длину инструкции> <инструкция>
    - ...

    """

    header = b"Pavel_CISC_ASM_code_file\n"

    max_debug_sub_str_len = 16
    max_debug_str_len = max_debug_sub_str_len * 2

    @staticmethod
    def number_to_big_endian(number: int, bytes_count: int):
        big_endian = []
        for i in range(bytes_count):
            big_endian.insert(0, number & 0xFF)
            number = number >> 8

        return big_endian

    @staticmethod
    def code_line_to_bytes(line):
        return ByteCodeFile.number_to_big_endian(line["mem_address"], 2) + ByteCodeFile.number_to_big_endian(len(line["byte_code"]), 2) + line["byte_code"]

    @staticmethod
    def code_to_bytes(code):
        byte_code = []
        for line in code:
            byte_code.extend(ByteCodeFile.code_line_to_bytes(line))
        return bytes(ByteCodeFile.header + ByteCodeFile.number_to_big_endian(len(code), 2) + byte_code)

    @staticmethod
    def code_to_debug(code):
        debug = "Code lines count = {} | {}\n".format(len(code), hex(len(code)))
        debug += "<address> - <hex asm> - <mnemonic>\n"

        lines = []
        for line in code:
            hex_address = hex(line["mem_address"])[2:]
            repeat = 4 - len(hex_address)
            if repeat > 0:
                hex_address = "0" * repeat + hex_address

            byte_code = " ".join([hex(byte)[2:] for byte in line["byte_code"]])

            if len(byte_code) > ByteCodeFile.max_debug_str_len:
                byte_code = byte_code[:ByteCodeFile.max_debug_sub_str_len] + "... " + byte_code[-ByteCodeFile.max_debug_sub_str_len:]

            mnemonic =  line["term"].mnemonic

            if len(mnemonic) > ByteCodeFile.max_debug_str_len:
                mnemonic = mnemonic[:ByteCodeFile.max_debug_sub_str_len] + "... " + mnemonic[-ByteCodeFile.max_debug_sub_str_len:]

            lines.append("{} - {} - {}".format(hex_address, byte_code, mnemonic))

        return debug + "\n".join(lines)

    @staticmethod
    def write(filename, code):
        """
        Записать машинный код в файл.
        """

        with open(filename, "wb") as file:
            file.write(ByteCodeFile.code_to_bytes(code))
            file.close()

    @staticmethod
    def write_debug(filename, code):
        """
        Записать код в виде:

        Code lines count = <>

        <address> - <hex asm> - <mnemonic>

        <address> - <hex asm> - <mnemonic>

        ...
        """

        with open(filename, "w") as file:
            file.write(ByteCodeFile.code_to_debug(code))
            file.close()

    @staticmethod
    def check_header(header):
        return header == ByteCodeFile.header

    @staticmethod
    def read_code(filename):
        """
        Прочесть бинарный машинный код из файла.
        """

        code = []

        with open(filename, "rb") as file:
            if not ByteCodeFile.check_header(file.read(len(ByteCodeFile.header))):
                raise Exception("У файла неправильный заголовок")

            code_lines_count = int.from_bytes(file.read(2), "big")

            for i in range(code_lines_count):
                mem_address = int.from_bytes(file.read(2), "big")
                instruction_len = int.from_bytes(file.read(2), "big")
                byte_code = [char for char in file.read(instruction_len)]

                code.append({"mem_address": mem_address, "byte_code": byte_code})

            file.close()

        return code


from collections import namedtuple


class OrgDirective:
    ORG = "org"


class DataTypeDirective:
    def __init__(self, name, bytes_count):
        self.name = name
        self.bytes_count = bytes_count
        self.max_uint = (1 << (bytes_count * 8)) - 1


class DataTypeDirectives:
    BYTE = DataTypeDirective("byte", 1)
    WORD = DataTypeDirective("word", 2)
    DWORD = DataTypeDirective("dword", 4)

    directives = [BYTE, WORD, DWORD]
    directive_by_name = {value.name: value for value in directives}

    @staticmethod
    def get_directive_by_name(name):
        return DataTypeDirectives.directive_by_name.get(name)


class InstructionPrefix:
    """
    Каждой инструкции с аргументом можно приписать директиву.
    Она определяет, с каким типом данных мы работаем в этой инструкции - `byte` или `word`
    Для `word` операндов префикс не ставится, но для удобства восприятия я его ввел
    """

    BYTE = 0xFF
    WORD = 0xFE
    DWORD = 0xFD


class InstructionPostfix:
    """
    Так как архитектура - CISC, то нужно как-то закодировать не всегда определенное количество аргументов.
    После кода инструкции будет следовать постфикс количества аргументов.
    По условию вроде требовалось бесконечно много, так что буду использовать `vlq`.

    После количества аргументов, для каждого будет 1 или несколько байт которые его определяют.
    Нужно будет определить:

    - значение на месте (`word` или `byte`) ИЛИ
    - регистр общего назначения (их 8) ИЛИ
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
    0 | 1 | is | os | s | s | i | o
    
    4 вида адресации можно закодировать в 2 бит
    
    scale_factor = 2 ^ s
    
    я не знаю зачем, но пусть будет:
    
    бит is == 0 => знак индекса "+"
    
    бит is == 1 => знак индекса "-" (предварительно взять доп. код)
    
    бит os == 0 => знак смещения "+"
    
    бит os == 1 => знак смещения "-" (предварительно взять доп. код)
    """

    arg_type_to_str = {
        ArgIsImmediate: "I",
        ArgIsRegister: "R",
        ArgsAreMemoryAddressing: "M"
    }

    OffsetAddressingFlag = 0x1
    IndexAddressingFlag = 0x2
    OffsetSignFlag = 0x8
    IndexSignFlag = 0x10

    valid_scale_factors = [value.bytes_count for value in DataTypeDirectives.directives]

    @staticmethod
    def like_arg_type(byte: int):
        byte = (byte & 0xC0) >> 6
        if byte == 0x3:
            return InstructionPostfix.ArgIsImmediate
        elif byte == 0x2:
            return InstructionPostfix.ArgIsRegister
        elif byte == 0x1:
            return InstructionPostfix.ArgsAreMemoryAddressing

        return byte

    @staticmethod
    def get_arg_type_str(arg_type: set):
        return "".join([InstructionPostfix.arg_type_to_str[key] for key in sorted(arg_type)])

    @staticmethod
    def encode_register(register_name: str):
        return InstructionPostfix.ArgIsRegister | Registers.general_register_to_code(register_name)

    @staticmethod
    def decode_register(byte: int):
        return Registers.code_to_general_register(byte & 0x7)

    @staticmethod
    def encode_addressing_mode(has_offset: bool, has_index: bool, scale_factor_power: int, offset_sign: bool,
                               index_sign: bool):
        byte = InstructionPostfix.ArgsAreMemoryAddressing
        if has_offset:
            byte = byte | InstructionPostfix.OffsetAddressingFlag

            if offset_sign:
                byte = byte | InstructionPostfix.OffsetSignFlag

        if has_index:
            byte = byte | InstructionPostfix.IndexAddressingFlag | ((scale_factor_power & 0x3) << 2)

            if index_sign:
                byte = byte | InstructionPostfix.IndexSignFlag

        return byte

    @staticmethod
    def decode_addressing_mode(byte: int):
        has_offset = byte & 0x1
        byte = byte >> 1

        has_index = byte & 0x1
        byte = byte >> 1

        scale_factor_power = byte & 0x3
        byte = byte >> 2

        offset_sign = byte & 0x1
        byte = byte >> 1

        index_sign = byte & 0x1

        return has_offset, has_index, scale_factor_power, offset_sign, index_sign


class Instruction:
    def __init__(self, mnemonic: str, opcode: int, args_types: list, variable_args_count=False,
                 validate_directive_and_args=lambda directive, args: (True, "Описание как правильно")):
        self.mnemonic = mnemonic
        self.opcode = opcode
        self.args_types = args_types
        self.variable_args_count = variable_args_count
        self.validate_directive_and_args = validate_directive_and_args


def jumps_validator(directive: DataTypeDirectives, args: list):
    return (
        directive is DataTypeDirectives.WORD,
        "Переходы требуют адрес в размере {} байта".format(DataTypeDirectives.WORD.bytes_count)
    )


class InstructionSet:
    """
    Определение кодирования и типов аргументов инструкции. Всего 42 инструкции (можно закодировать с помощью 6 бит).
    Они шаблонно разделены по количеству используемых аргументов.

    Аргументы инструкций = [<destination>, <source1>, <source2>, ...]

    Инструкции без аргументов:

    0 | 0 | x | x | x | x | x | x

    Инструкции с 1 аргументом:

    0 | 1 | w | x | x | x | x | x

    бит w == 0 => любое

    бит w == 1 => нужно иметь возможность записать (регистр, память)

    Инструкции с 2 аргументами:

    1 | 0 | x | x | x | x | x | x

    В первый аргумент точно будем писать (может еще читать), из второго - только читать

    Инструкции с N аргументами:

    1 | 1 | 0 | 0 | x | x | x | x

    В первый аргумент точно будем писать (может еще читать), из остальных - только читать
    """

    arg_is_only_register = {InstructionPostfix.ArgIsRegister}
    arg_is_writeable = {InstructionPostfix.ArgIsRegister, InstructionPostfix.ArgsAreMemoryAddressing}
    arg_is_any = {InstructionPostfix.ArgIsImmediate, InstructionPostfix.ArgIsRegister,
                  InstructionPostfix.ArgsAreMemoryAddressing}

    # Инструкции без аргументов (10)
    NOP = Instruction("nop", 0x00, [])
    HALT = Instruction("halt", 0x01, [])
    CLC = Instruction("clc", 0x02, [])
    CMC = Instruction("cmc", 0x03, [])

    PUSHF = Instruction("pushf", 0x04, [])
    POPF = Instruction("popf", 0x05, [])

    EI = Instruction("ei", 0x06, [])
    DI = Instruction("di", 0x07, [])
    RET = Instruction("ret", 0x08, [])
    IRET = Instruction("iret", 0x09, [])

    # Инструкции с 1 аргументом (20)
    NOT = Instruction("not", 0x60, [arg_is_writeable])
    NEG = Instruction("neg", 0x61, [arg_is_writeable])
    INC = Instruction("inc", 0x62, [arg_is_writeable])
    DEC = Instruction("dec", 0x63, [arg_is_writeable])
    SXT = Instruction("sxt", 0x64, [arg_is_writeable])
    SWAB = Instruction("swab", 0x65, [arg_is_only_register])

    JMP = Instruction("jmp", 0x40, [arg_is_any], validate_directive_and_args=jumps_validator)

    JE = Instruction("je", 0x41, [arg_is_any], validate_directive_and_args=jumps_validator)
    JZ = Instruction("jz", 0x41, [arg_is_any], validate_directive_and_args=jumps_validator)
    JNE = Instruction("jne", 0x42, [arg_is_any], validate_directive_and_args=jumps_validator)
    JNZ = Instruction("jnz", 0x42, [arg_is_any], validate_directive_and_args=jumps_validator)

    JG = Instruction("jg", 0x43, [arg_is_any], validate_directive_and_args=jumps_validator)
    JGE = Instruction("jge", 0x44, [arg_is_any], validate_directive_and_args=jumps_validator)

    JA = Instruction("ja", 0x45, [arg_is_any], validate_directive_and_args=jumps_validator)
    JAE = Instruction("jae", 0x46, [arg_is_any], validate_directive_and_args=jumps_validator)

    JL = Instruction("jl", 0x47, [arg_is_any], validate_directive_and_args=jumps_validator)
    JLE = Instruction("jle", 0x48, [arg_is_any], validate_directive_and_args=jumps_validator)

    JB = Instruction("jb", 0x49, [arg_is_any], validate_directive_and_args=jumps_validator)
    JC = Instruction("jc", 0x49, [arg_is_any], validate_directive_and_args=jumps_validator)
    JBE = Instruction("jbe", 0x4A, [arg_is_any], validate_directive_and_args=jumps_validator)

    JS = Instruction("js", 0x4B, [arg_is_any], validate_directive_and_args=jumps_validator)
    JNS = Instruction("jns", 0x4C, [arg_is_any], validate_directive_and_args=jumps_validator)

    JNC = Instruction("jnc", 0x4E, [arg_is_any], validate_directive_and_args=jumps_validator)

    JV = Instruction("jv", 0x4D, [arg_is_any], validate_directive_and_args=jumps_validator)
    JNV = Instruction("jnv", 0x4F, [arg_is_any], validate_directive_and_args=jumps_validator)

    LOOP = Instruction("loop", 0x70, [arg_is_writeable])

    PUSH = Instruction("push", 0x50, [arg_is_any])
    CALL = Instruction("call", 0x51, [arg_is_any], validate_directive_and_args=jumps_validator)
    POP = Instruction("pop", 0x71, [arg_is_writeable])

    INT = Instruction("int", 0x52, [arg_is_any])

    # Инструкции с 2 аргументами (11)
    MOV = Instruction("mov", 0x80, [arg_is_writeable, arg_is_any])

    AND = Instruction("and", 0x90, [arg_is_writeable, arg_is_any])
    OR = Instruction("or", 0x91, [arg_is_writeable, arg_is_any])
    XOR = Instruction("xor", 0x92, [arg_is_writeable, arg_is_any])

    ADD = Instruction("add", 0xA0, [arg_is_writeable, arg_is_any])
    ADC = Instruction("adc", 0xA1, [arg_is_writeable, arg_is_any])
    SUB = Instruction("sub", 0xA2, [arg_is_writeable, arg_is_any])
    MUL = Instruction("mul", 0xA7, [arg_is_writeable, arg_is_any])
    DIV = Instruction("div", 0xA8, [arg_is_writeable, arg_is_any])
    MOD = Instruction("mod", 0xA9, [arg_is_writeable, arg_is_any])

    CMP = Instruction("cmp", 0xB0, [arg_is_any, arg_is_any])
    SWAP = Instruction("swap", 0xB1, [arg_is_writeable, arg_is_writeable])

    # Инструкции с N аргументами (1)
    LCOMB = Instruction("lcomb", 0xC0, [arg_is_any], True, lambda directive, args: (
    len(args) % 2 == 1, "Требует нечетное количество элементов: c0 + c1x1 + ..."))

    mnemonic_to_instruction_dict = {
        NOP.mnemonic: NOP,
        HALT.mnemonic: HALT,
        CLC.mnemonic: CLC,
        CMC.mnemonic: CMC,
        EI.mnemonic: EI,
        DI.mnemonic: DI,
        RET.mnemonic: RET,
        IRET.mnemonic: IRET,
        NOT.mnemonic: NOT,
        NEG.mnemonic: NEG,
        INC.mnemonic: INC,
        DEC.mnemonic: DEC,
        SXT.mnemonic: SXT,
        SWAB.mnemonic: SWAB,

        JMP.mnemonic: JMP,

        JE.mnemonic: JE,
        JZ.mnemonic: JZ,
        JNE.mnemonic: JNE,
        JNZ.mnemonic: JNZ,

        JG.mnemonic: JG,
        JGE.mnemonic: JGE,

        JA.mnemonic: JA,
        JAE.mnemonic: JAE,

        JL.mnemonic: JL,
        JLE.mnemonic: JLE,

        JB.mnemonic: JB,
        JC.mnemonic: JC,
        JBE.mnemonic: JBE,

        JS.mnemonic: JS,
        JNS.mnemonic: JNS,

        JNC.mnemonic: JNC,

        JV.mnemonic: JV,
        JNV.mnemonic: JNV,

        LOOP.mnemonic: LOOP,
        PUSH.mnemonic: PUSH,
        POP.mnemonic: POP,
        CALL.mnemonic: CALL,
        INT.mnemonic: INT,
        MOV.mnemonic: MOV,
        AND.mnemonic: AND,
        OR.mnemonic: OR,
        XOR.mnemonic: XOR,
        ADD.mnemonic: ADD,
        ADC.mnemonic: ADC,
        SUB.mnemonic: SUB,
        MUL.mnemonic: MUL,
        DIV.mnemonic: DIV,
        MOD.mnemonic: MOD,
        CMP.mnemonic: CMP,
        SWAP.mnemonic: SWAP,
        LCOMB.mnemonic: LCOMB
    }

    opcode_to_instruction_dict = {
        value.opcode: value for value in mnemonic_to_instruction_dict.values()
    }

    @staticmethod
    def opcode_to_instruction(opcode: int):
        try:
            return InstructionSet.opcode_to_instruction_dict[opcode]
        except Exception as e:
            return InstructionSet.NOP

    @staticmethod
    def check_types_are_equal(arg_types1: set, arg_types2: set):
        return arg_types1 == arg_types2

    @staticmethod
    def check_type_is_valid(arg_type: int, arg_types: set):
        return arg_type in arg_types

    @staticmethod
    def form_args_types_str(args_types: list, variable_args_count: bool):
        if not variable_args_count:
            return ", ".join([InstructionPostfix.get_arg_type_str(arg_types) for arg_types in args_types])

        return InstructionSet.form_args_types_str(args_types[:-1], False) + "[ , {} ]".format(
            InstructionSet.form_args_types_str(args_types[-1], False))

    @staticmethod
    def form_arg_type(is_number: bool, is_label: bool, is_register: bool):
        if is_number or is_label:
            return InstructionPostfix.ArgIsImmediate

        if is_register:
            return InstructionPostfix.ArgIsRegister

        return InstructionPostfix.ArgsAreMemoryAddressing

    @staticmethod
    def valid_args_types(opcode: int, args_types: list):
        instruction = InstructionSet.opcode_to_instruction(opcode)
        for i, arg_types in enumerate(args_types):
            if arg_types != instruction.args_types[i]:
                return False
        return True


class Register:
    def __init__(self, name: str, code: int, byte_size: int, is_left: bool):
        self.name = name
        self.code = code
        self.byte_size = byte_size
        self.max_uint = (1 << byte_size * 8) - 1
        self.value = 0
        self.is_left = is_left

    def set(self, value: int):
        self.value = value & self.max_uint

    def get(self):
        return self.value


class DataRegister(Register):
    def __init__(self, name, code, byte_size, is_left):
        super().__init__(name, code, byte_size, is_left)

    def set_from_input(self, value, io_data_max_uint):
        self.value = (self.value & (self.max_uint - io_data_max_uint)) | value

    def get_byte(self):
        return self.value & 0xFF


class ProgramStateRegister(Register):
    def __init__(self, name, code, byte_size, is_left):
        super().__init__(name, code, byte_size, is_left)

    def set_w(self, w: int = None):
        if w is not None:
            assert w == 0 or w == 1, "Сигналы принимают значения 0 или 1"
            self.value = (self.value & 0x7F) | (w << 6)

    def get_w(self):
        return (self.value >> 6) & 1

    def set_i(self, i: int = None):
        if i is not None:
            assert i == 0 or i == 1, "Сигналы принимают значения 0 или 1"
            self.value = (self.value & 0x5F) | (i << 5)

    def get_i(self):
        return (self.value >> 5) & 1

    def set_ei(self, ei: int = None):
        if ei is not None:
            assert ei == 0 or ei == 1, "Сигналы принимают значения 0 или 1"
            self.value = (self.value & 0x6F) | (ei << 4)

    def get_ei(self):
        return (self.value >> 4) & 1

    def set_n(self, n: int = None):
        if n is not None:
            assert n == 0 or n == 1, "Сигналы принимают значения 0 или 1"
            self.value = (self.value & 0x77) | (n << 3)

    def get_n(self):
        return (self.value >> 3) & 1

    def set_z(self, z: int = None):
        if z is not None:
            assert z == 0 or z == 1, "Сигналы принимают значения 0 или 1"
            self.value = (self.value & 0x7B) | (z << 2)

    def get_z(self):
        return (self.value >> 2) & 1

    def set_v(self, v: int = None):
        if v is not None:
            assert v == 0 or v == 1, "Сигналы принимают значения 0 или 1"
            self.value = (self.value & 0x7D) | (v << 1)

    def get_v(self):
        return (self.value >> 1) & 1

    def set_c(self, c: int = None):
        if c is not None:
            assert c == 0 or c == 1, "Сигналы принимают значения 0 или 1"
            self.value = (self.value & 0x7E) | c

    def get_c(self):
        return self.value & 1


class Registers:
    """
    Каждый регистр (кроме "program state") имеет размер 1 слово (2 байт)

    PS представляет собой последовательность:

    w | i | ei | n | z | v | c
    """

    register_max_size_in_bytes = DataTypeDirectives.DWORD.bytes_count
    register_max_uint = (1 << register_max_size_in_bytes * 8) - 1

    # Регистры общего назначения (8)
    SP = Register("sp", 0, DataTypeDirectives.WORD.bytes_count, False)
    "Указатель на стек"

    R1 = Register("r1", 1, DataTypeDirectives.DWORD.bytes_count, True)
    R2 = Register("r2", 2, DataTypeDirectives.DWORD.bytes_count, True)
    R3 = Register("r3", 3, DataTypeDirectives.DWORD.bytes_count, True)
    R4 = Register("r4", 4, DataTypeDirectives.DWORD.bytes_count, True)
    R5 = Register("r5", 5, DataTypeDirectives.DWORD.bytes_count, False)
    R6 = Register("r6", 6, DataTypeDirectives.DWORD.bytes_count, False)
    R7 = Register("r7", 7, DataTypeDirectives.DWORD.bytes_count, False)

    # Специальные регистры (7), их нельзя использовать как аргументы в инструкциях
    # Но есть инструкции которые работают с ними
    AR = Register("ar", -1, DataTypeDirectives.WORD.bytes_count, False)

    DR = DataRegister("dr", -1, DataTypeDirectives.DWORD.bytes_count, False)

    ABR1 = Register("abr1", -1, DataTypeDirectives.WORD.bytes_count, True)
    ABR2 = Register("abr2", -1, DataTypeDirectives.WORD.bytes_count, True)
    ABR3 = Register("abr3", -1, DataTypeDirectives.WORD.bytes_count, False)
    DN = Register("dn", -1, DataTypeDirectives.WORD.bytes_count, False)

    AC = Register("ac", -1, DataTypeDirectives.DWORD.bytes_count, True)
    BR1 = Register("br1", -1, DataTypeDirectives.DWORD.bytes_count, True)
    BR2 = Register("br2", -1, DataTypeDirectives.DWORD.bytes_count, False)
    BR3 = Register("br3", -1, DataTypeDirectives.DWORD.bytes_count, False)

    IP = Register("ip", -1, DataTypeDirectives.WORD.bytes_count, False)
    CR = Register("cr", -1, DataTypeDirectives.WORD.bytes_count, False)
    PS = ProgramStateRegister("ps", -1, DataTypeDirectives.BYTE.bytes_count, False)

    general_registers_list = [SP, R1, R2, R3, R4, R5, R6, R7]
    code_to_general_register_dict = {value.code: value for value in general_registers_list}
    general_register_name_to_code_dict = {value.name: value.code for value in code_to_general_register_dict.values()}

    @staticmethod
    def code_to_general_register(code: int):
        return Registers.code_to_general_register_dict[code]

    @staticmethod
    def general_register_to_code(reg: str):
        return Registers.general_register_name_to_code_dict[reg]


class Term(namedtuple("Term", "line mnemonic")):
    """Описание выражения из исходного текста программы.

    Сделано через класс, чтобы был docstring.
    """


class ByteCodeFile:
    """
    Структура файла такая:

    - 'уникальный' заголовок
    - <2 байта на метку 'start'>
    - <2 байта на количество инструкций>
    - <2 байта на адрес> <2 байта на длину инструкции> <инструкция>
    - <2 байта на адрес> <2 байта на длину инструкции> <инструкция>
    - ...

    """

    int_header = [ord(char) for char in "Pavel_CISC_ASM_code_file\n"]
    bytes_header = bytes(int_header)

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
        return ByteCodeFile.number_to_big_endian(line["mem_address"], 2) + ByteCodeFile.number_to_big_endian(
            len(line["byte_code"]), 2) + line["byte_code"]

    @staticmethod
    def code_to_bytes(start_address: int, code):
        byte_code = []
        for line in code:
            byte_code.extend(ByteCodeFile.code_line_to_bytes(line))
        return bytes(ByteCodeFile.int_header + ByteCodeFile.number_to_big_endian(start_address,
                                                                                 2) + ByteCodeFile.number_to_big_endian(
            len(code), 2) + byte_code)

    @staticmethod
    def code_to_debug(start_address: int, code):
        debug = "Start address = {}\nCode lines count = {} | {}\n".format(start_address, len(code), hex(len(code)))
        debug += "<address> - <hex asm> - <mnemonic>\n"

        lines = []
        for line in code:
            hex_address = hex(line["mem_address"])[2:]
            repeat = 4 - len(hex_address)
            if repeat > 0:
                hex_address = "0" * repeat + hex_address

            byte_code = " ".join([hex(byte)[2:] for byte in line["byte_code"]])

            if len(byte_code) > ByteCodeFile.max_debug_str_len:
                byte_code = byte_code[:ByteCodeFile.max_debug_sub_str_len] + "... " + byte_code[
                                                                                      -ByteCodeFile.max_debug_sub_str_len:]

            mnemonic = line["term"].mnemonic

            if len(mnemonic) > ByteCodeFile.max_debug_str_len:
                mnemonic = mnemonic[:ByteCodeFile.max_debug_sub_str_len] + "... " + mnemonic[
                                                                                    -ByteCodeFile.max_debug_sub_str_len:]

            lines.append("{} - {} - {}".format(hex_address, byte_code, mnemonic))

        return debug + "\n".join(lines)

    @staticmethod
    def write(filename, start_address, code):
        """
        Записать машинный код в файл.
        """

        with open(filename, "wb") as file:
            file.write(ByteCodeFile.code_to_bytes(start_address, code))

    @staticmethod
    def write_debug(filename, start_address, code):
        """
        Записать код в виде:

        Code lines count = <>

        <address> - <hex asm> - <mnemonic>

        <address> - <hex asm> - <mnemonic>

        ...
        """

        with open(filename, "w", encoding="utf-8") as file:
            file.write(ByteCodeFile.code_to_debug(start_address, code))

    @staticmethod
    def check_header(header: bytes):
        return header == ByteCodeFile.bytes_header

    @staticmethod
    def read_code(filename):
        """
        Прочесть бинарный машинный код из файла.
        """

        start_address = 0
        code = []

        with open(filename, "rb") as file:
            if not ByteCodeFile.check_header(file.read(len(ByteCodeFile.int_header))):
                raise Exception("У файла неправильный заголовок")

            start_address = int.from_bytes(file.read(2), "big")
            code_lines_count = int.from_bytes(file.read(2), "big")

            for i in range(code_lines_count):
                mem_address = int.from_bytes(file.read(2), "big")
                instruction_len = int.from_bytes(file.read(2), "big")
                byte_code = [char for char in file.read(instruction_len)]

                code.append({"mem_address": mem_address, "byte_code": byte_code})

        return start_address, code

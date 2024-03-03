import isa
import logging
import re
import sys
import translator


class Exceptions:
    class StopModellingError(Exception):
        def __init__(self, msg):
            super().__init__(msg)

    class EntryPointError(StopModellingError):
        def __init__(self, msg):
            super().__init__(
                "Адрес метки входа: {}, не может быть меньше 0 или больше {}"
                    .format(msg, hex(DataPath.memory_max_uint))
            )

    class VarArgsCountError(StopModellingError):
        def __init__(self, msg):
            super().__init__(
                "Переменное количество аргументов: {}, не может быть меньше 0 или больше {}"
                    .format(msg, 255)
            )


class Device:
    def __init__(self, buffer: list):
        self.ready = 1
        self.current_time = 0
        self.buffer = buffer

    def live(self):
        self.current_time += 1

    def get_buffer(self):
        return self.buffer


class InputDevice(Device):
    def __init__(self, input_buffer: list):
        super().__init__(input_buffer)
        self.current_token = 0

    def live(self):
        super().live()

        if self.current_token >= len(self.buffer):
            self.ready = 0
            return

        time, token = self.buffer[self.current_token]
        if self.current_time >= time:
            if self.ready == 0:
                self.current_token += 1
            self.ready = 1

    def get_current_token(self):
        if self.current_token >= len(self.buffer):
            return 0

        time, token = self.buffer[self.current_token]
        return token


class OutputDevice(Device):
    def __init__(self, output_buffer: list):
        super().__init__(output_buffer)
        self.ready = 0

    def add_token(self, token: int):
        if self.ready == 0:
            return

        self.ready = 0
        self.buffer.append(token)

    def live(self):
        super().live()

        if len(self.buffer) > 0 and self.buffer[-1] == 0:
            self.ready = 0
        else:
            self.ready = 1


class DeviceMux:
    def __init__(self):
        self.data = 0
        self.max_uint = 0xFF


class ALU:
    sign_bit = ((isa.Registers.register_max_size_in_bytes * 8) - 1)
    result_max_uint = isa.Registers.register_max_uint
    minus_one = result_max_uint
    available_signals = [0, 1]

    def __init__(self, data_path):
        self.data_path = data_path
        self.left = 0
        self.right = 0
        self.sign_extend = 0
        self.result = 0
        self.n_flag = 0
        self.z_flag = 0
        self.v_flag = 0
        self.c_flag = 0

    def signal_set_ac_to_left(self):
        self.left = self.data_path.ac.get()

    def signal_set_br1_to_left(self):
        self.left = self.data_path.buffer_register1.get()

    def signal_set_abr1_to_left(self):
        self.left = self.data_path.address_buffer_register1.get()

    def signal_set_abr2_to_left(self):
        self.left = self.data_path.address_buffer_register2.get()

    def signal_set_r1_to_left(self):
        self.left = self.data_path.r1.get()

    def signal_set_r2_to_left(self):
        self.left = self.data_path.r2.get()

    def signal_set_r3_to_left(self):
        self.left = self.data_path.r3.get()

    def signal_set_r4_to_left(self):
        self.left = self.data_path.r4.get()

    def signal_set_r5_to_right(self):
        self.right = self.data_path.r5.get()

    def signal_set_r6_to_right(self):
        self.right = self.data_path.r6.get()

    def signal_set_r7_to_right(self):
        self.right = self.data_path.r7.get()

    def signal_set_abr3_to_right(self):
        self.right = self.data_path.address_buffer_register3.get()

    def signal_set_dn_to_right(self):
        self.right = self.data_path.destination_register.get()

    def signal_set_br2_to_right(self):
        self.right = self.data_path.buffer_register2.get()

    def signal_set_br3_to_right(self):
        self.right = self.data_path.buffer_register3.get()

    def signal_set_ip_to_right(self):
        self.right = self.data_path.instruction_pointer.get()

    def signal_set_ar_to_right(self):
        self.right = self.data_path.address_register.get()

    def signal_set_cr_to_right(self):
        self.right = self.data_path.command_register.get()

    def signal_set_dr_to_right(self):
        self.right = self.data_path.data_register.get()

    def signal_set_sp_to_right(self):
        self.right = self.data_path.stack_pointer.get()

    def signal_set_ps_to_right(self):
        self.right = self.data_path.program_state.get()

    def get_nzvc_by_result(self, result):
        n_flag = ((result >> self.sign_bit) & 1) == 1
        z_flag = (result & self.result_max_uint) == 0
        c_flag = (result >> (self.sign_bit + 1) & 1) == 1
        v_flag = (n_flag == c_flag)

        return n_flag, z_flag, v_flag, c_flag

    def get_result(self):
        return self.result

    def set_result(self, result, edit_n=False, edit_z=False, edit_v=False, edit_c=False):
        self.n_flag = self.data_path.program_state.get_n()
        self.z_flag = self.data_path.program_state.get_z()
        self.v_flag = self.data_path.program_state.get_v()
        self.c_flag = self.data_path.program_state.get_c()

        if self.sign_extend == 1:
            # Расширение знака байта
            self.sign_extend = 0
            bit_value = (result >> 7) & 1

            high = ((self.result_max_uint + 1) - (1 << 8)) & bit_value
            low = result & ((1 << 8) - 1)

            result = high | low
            edit_n = True
        elif self.sign_extend == 2:
            # Расширение знака слова
            self.sign_extend = 0
            bit_value = (result >> 15) & 1

            high = ((self.result_max_uint + 1) - (1 << 16)) & bit_value
            low = result & ((1 << 16) - 1)

            result = high | low
            edit_n = True

        n_flag, z_flag, v_flag, c_flag = self.get_nzvc_by_result(result)
        self.result = result & self.result_max_uint

        if edit_n:
            self.n_flag = n_flag
        if edit_z:
            self.z_flag = z_flag
        if edit_v:
            self.v_flag = v_flag
        if edit_c:
            self.c_flag = c_flag

        self.data_path.program_state.set_n(self.n_flag)
        self.data_path.program_state.set_z(self.z_flag)
        self.data_path.program_state.set_v(self.v_flag)
        self.data_path.program_state.set_c(self.c_flag)

        self.left = 0
        self.right = 0

    def set_hidden_nzvc(self, n_flag: int = -1, z_flag: int = -1, v_flag: int = -1, c_flag: int = -1):
        if n_flag in self.available_signals:
            self.n_flag = n_flag & 1
        if z_flag in self.available_signals:
            self.z_flag = z_flag & 1
        if v_flag in self.available_signals:
            self.v_flag = v_flag & 1
        if c_flag in self.available_signals:
            self.c_flag = c_flag & 1

    def clear_left(self):
        self.left = 0

    def clear_right(self):
        self.right = 0

    def signal_decode_scale_factor(self, left: bool):
        value = self.left if left else self.right
        self.set_result((value >> 2) & 3)

    def signal_inc(self, edit_flags: bool, left: bool):
        if left:
            self.set_result(self.left + 1, edit_flags, edit_flags, edit_flags, edit_flags)
        else:
            self.set_result(self.right + 1, edit_flags, edit_flags, edit_flags, edit_flags)

    def signal_dec(self, edit_flags: bool, left: bool):
        if left:
            self.set_result(self.left + self.minus_one, edit_flags, edit_flags, edit_flags, edit_flags)
        else:
            self.set_result(self.right + self.minus_one, edit_flags, edit_flags, edit_flags, edit_flags)

    def signal_neg(self, left: bool):
        if left:
            self.left = self.result_max_uint + 1 - self.left
        else:
            self.right = self.result_max_uint + 1 - self.right

    def signal_add(self, add_carry: bool):
        if add_carry:
            self.set_result(self.left + self.right + self.c_flag, edit_n=True, edit_c=True, edit_z=True, edit_v=True)
        else:
            self.set_result(self.left + self.right, edit_n=True, edit_c=True, edit_z=True, edit_v=True)

    def signal_sub(self):
        self.set_result(self.left + (self.result_max_uint + 1 - self.right), edit_n=True, edit_c=True, edit_z=True,
                        edit_v=True)

    def signal_mul(self):
        self.set_result(self.left * self.right, edit_n=True, edit_c=True, edit_z=True, edit_v=True)

    def signal_div(self):
        self.set_result(self.left // self.right, edit_n=True, edit_c=True, edit_z=True, edit_v=True)

    def signal_mod(self):
        self.set_result(self.left % self.right, edit_n=True, edit_c=True, edit_z=True, edit_v=True)

    def signal_rol(self, left: bool):
        value = self.left if left else self.right
        self.set_result((value << 1) | self.c_flag, edit_c=True)

    def signal_ror(self, left: bool):
        value = self.left if left else self.right
        sign = self.c_flag << self.sign_bit
        self.set_result(sign | (value >> 1))
        self.set_hidden_nzvc(n_flag=-1, z_flag=-1, v_flag=-1, c_flag=value & 1)

    def signal_asl(self, left: bool):
        value = self.left if left else self.right
        self.set_result(value << 1, edit_c=True)

    def signal_asr(self, left: bool):
        value = self.left if left else self.right
        sign = (value >> self.sign_bit) & 1 << self.sign_bit
        self.set_hidden_nzvc(n_flag=-1, z_flag=-1, v_flag=-1, c_flag=value & 1)
        self.set_result(sign | (value >> 1))

    def signal_sxt(self, is_byte: bool):
        self.sign_extend = 1 if is_byte else 2

    def signal_swab(self, low_bytes: bool, left: bool):
        value = self.left if left else self.right
        bits_count = 8 if low_bytes else 16
        mask = (1 << bits_count) - 1

        low = value & mask
        high = (value >> bits_count) & mask

        self.set_result(value & (self.result_max_uint - mask) | (high << bits_count) | low)

    def signal_lshift_byte(self, left: bool):
        value = self.left if left else self.right
        high = (value & 0x00FFFFFF) << 8
        low = (value & 0xFF000000) >> 24
        self.set_result(high | low)

    def signal_rshift_byte(self, left: bool):
        value = self.left if left else self.right
        high = (value & 0x000000FF) << 24
        low = (value & 0xFFFFFF00) >> 8
        self.set_result(high | low)

    def signal_not(self, left: bool):
        if left:
            self.left = self.result_max_uint - self.left
        else:
            self.right = self.result_max_uint - self.right

    def signal_and(self):
        self.set_result(self.left & self.right)

    def signal_or(self):
        self.set_result(self.left | self.right)

    def signal_xor(self):
        self.set_result(self.left ^ self.right)


class AddressCodeDecoder:
    def __init__(self, data_path):
        self.data_path = data_path

    def signal_read(self):
        address = self.data_path.address_register.get()
        if 0x10 <= address < 0x14:
            # Устройства ввода вывода
            is_status_byte = (address & 1) == 0
            if address < 0x12:
                # Устройство ввода
                if is_status_byte:
                    self.data_path.input_device_mux.data = self.data_path.input_device.ready
                else:
                    self.data_path.input_device_mux.data = self.data_path.input_device.get_current_token()
            else:
                # Устройство вывода
                if is_status_byte:
                    self.data_path.input_device_mux.data = self.data_path.output_device.ready
                else:
                    pass
        else:
            # Устройство памяти
            self.data_path.input_device_mux.data = self.data_path.memory[address]

    def signal_write(self):
        address = self.data_path.address_register.get()
        if 0x10 <= address < 0x14:
            # Устройства ввода вывода
            is_status_byte = (address & 1) == 0
            if address < 0x12:
                # Устройство ввода
                if is_status_byte:
                    self.data_path.input_device.ready = self.data_path.output_device_mux.data
                else:
                    pass
            else:
                # Устройство вывода
                if is_status_byte:
                    self.data_path.output_device.ready = 0
                else:
                    self.data_path.output_device.add_token(self.data_path.output_device_mux.data)
        else:
            # Устройство памяти
            self.data_path.memory[address] = self.data_path.output_device_mux.data + 0


class DataPath:
    qword_max_uint = (1 << 32) - 1
    word_max_uint = (1 << 16) - 1
    byte_max_uint = (1 << 8) - 1

    memory_address_size_in_bytes = 2
    memory_max_uint = (1 << memory_address_size_in_bytes * 8) - 1

    memory_word_in_bytes = 1
    memory_word = (1 << memory_word_in_bytes * 8) - 1

    io_data_size_in_bytes = 1
    io_data_max_uint = (1 << io_data_size_in_bytes * 8) - 1
    available_signals = [0, 1]

    def __init__(self, start_address, code, input_device, output_device):
        if not (0 <= start_address <= DataPath.memory_max_uint):
            raise Exceptions.EntryPointError(start_address)

        self.memory = [0] * (DataPath.memory_max_uint + 1)
        self.input_device = input_device
        self.output_device = output_device

        # Пихаем программу в устройство памяти
        for line in code:
            mem_address = line["mem_address"]
            for byte in line["byte_code"]:
                self.memory[mem_address] = byte
                mem_address += 1

        # Регистры слева от АЛУ
        self.r1 = isa.Registers.R1
        self.r2 = isa.Registers.R2
        self.r3 = isa.Registers.R3
        self.r4 = isa.Registers.R4
        self.ac = isa.Registers.AC
        self.buffer_register1 = isa.Registers.BR1
        self.address_buffer_register1 = isa.Registers.ABR1
        self.address_buffer_register2 = isa.Registers.ABR2

        # Регистры справа от АЛУ
        self.r5 = isa.Registers.R5
        self.r6 = isa.Registers.R6
        self.r7 = isa.Registers.R7
        self.buffer_register2 = isa.Registers.BR2
        self.buffer_register3 = isa.Registers.BR3
        self.address_buffer_register3 = isa.Registers.ABR3
        self.destination_register = isa.Registers.DN

        self.instruction_pointer = isa.Registers.IP
        self.instruction_pointer.set(start_address)

        self.address_register = isa.Registers.AR
        self.command_register = isa.Registers.CR
        self.data_register = isa.Registers.DR
        self.stack_pointer = isa.Registers.SP
        self.program_state = isa.Registers.PS
        self.signal_set_ps(w=1)

        # Другие участки схемы
        self.alu = ALU(self)
        self.address_code_decoder = AddressCodeDecoder(self)
        self.input_device_mux = DeviceMux()
        self.output_device_mux = DeviceMux()

    def signal_latch_r1(self):
        self.r1.set(self.alu.get_result())

    def signal_latch_r2(self):
        self.r2.set(self.alu.get_result())

    def signal_latch_r3(self):
        self.r3.set(self.alu.get_result())

    def signal_latch_r4(self):
        self.r4.set(self.alu.get_result())

    def signal_latch_r5(self):
        self.r5.set(self.alu.get_result())

    def signal_latch_r6(self):
        self.r6.set(self.alu.get_result())

    def signal_latch_r7(self):
        self.r7.set(self.alu.get_result())

    def signal_latch_abr1(self):
        self.address_buffer_register1.set(self.alu.get_result())

    def signal_latch_abr2(self):
        self.address_buffer_register2.set(self.alu.get_result())

    def signal_latch_abr3(self):
        self.address_buffer_register3.set(self.alu.get_result())

    def signal_latch_dn(self):
        self.destination_register.set(self.alu.get_result())

    def signal_latch_ac(self):
        self.ac.set(self.alu.get_result())

    def signal_latch_br1(self):
        self.buffer_register1.set(self.alu.get_result())

    def signal_latch_br2(self):
        self.buffer_register2.set(self.alu.get_result())

    def signal_latch_br3(self):
        self.buffer_register3.set(self.alu.get_result())

    def signal_latch_ip(self):
        self.instruction_pointer.set(self.alu.get_result())

    def signal_latch_ar(self):
        self.address_register.set(self.alu.get_result())

    def signal_latch_cr(self):
        self.command_register.set(self.alu.get_result())

    def signal_latch_dr(self):
        self.data_register.set(self.alu.get_result())

    def signal_latch_sp(self):
        self.stack_pointer.set(self.alu.get_result())

    def signal_latch_ps(self):
        self.program_state.set(self.alu.get_result())

    def signal_set_ps(self, w: int = -1, i: int = -1, ei: int = -1):
        if ei in self.available_signals:
            self.program_state.set_ei(ei)
        if i in self.available_signals:
            self.program_state.set_i(i)
        if w in self.available_signals:
            self.program_state.set_w(w)

    def signal_set_nzvc_from_alu(self, edit_n=True, edit_z=True, edit_v=True, edit_c=True):
        if edit_n:
            self.program_state.set_n(self.alu.n_flag)
        if edit_z:
            self.program_state.set_z(self.alu.z_flag)
        if edit_v:
            self.program_state.set_v(self.alu.v_flag)
        if edit_c:
            self.program_state.set_c(self.alu.c_flag)

    def signal_invert_carry(self):
        self.program_state.set_c(1 - self.program_state.get_c())

    def signal_clear_carry(self):
        self.program_state.set_c(0)

    def signal_read(self):
        self.address_code_decoder.signal_read()
        self.data_register.set_from_input(self.input_device_mux.data, self.input_device_mux.max_uint)

    def signal_write(self):
        self.output_device_mux.data = self.data_register.get_byte()
        self.address_code_decoder.signal_write()


class ControlUnit:
    def __init__(self, data_path: DataPath):
        self.data_path = data_path

        self._instruction_tick = 0
        "Текущее модельное время процессора (в инструкциях). Инициализируется нулём."

    def instruction_tick(self):
        """Продвинуть модельное время процессора вперёд на один такт."""
        self._instruction_tick += 1

    def current_tick(self):
        return self._instruction_tick

    def read_from_memory(self, directive):
        repeats = 1
        if directive == isa.InstructionPrefix.WORD:
            repeats = 2
        elif directive == isa.InstructionPrefix.DWORD:
            repeats = 4

        for i in range(repeats):
            # DR << 8 => DR
            self.data_path.alu.signal_set_dr_to_right()
            self.data_path.alu.signal_lshift_byte(left=False)
            self.data_path.signal_latch_dr()

            # IP => AR
            self.data_path.alu.signal_set_ip_to_right()
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_ar()

            # IP + 1 => IP
            self.data_path.alu.signal_set_ip_to_right()
            self.data_path.alu.signal_inc(edit_flags=False, left=False)
            self.data_path.signal_latch_ip()

            # MEM[AR] => DR[7..0]
            self.data_path.signal_read()

    def write_to_memory(self, directive):
        repeats = 1
        if directive == isa.InstructionPrefix.WORD:
            repeats = 2
        elif directive == isa.InstructionPrefix.DWORD:
            repeats = 4

        for i in range(repeats - 1):
            # DR >> 8 => DR
            self.data_path.alu.signal_set_dr_to_right()
            self.data_path.alu.signal_rshift_byte(left=False)
            self.data_path.signal_latch_dr()

        for i in range(repeats):
            # DN => AR
            self.data_path.alu.signal_set_dn_to_right()
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_ar()

            # DN + 1 => DN
            self.data_path.alu.signal_set_dn_to_right()
            self.data_path.alu.signal_inc(edit_flags=False, left=False)
            self.data_path.signal_latch_dn()

            # DR[7..0] => MEM[AR]
            self.data_path.signal_write()

            # DR << 8 => DR
            self.data_path.alu.signal_set_dr_to_right()
            self.data_path.alu.signal_lshift_byte(left=False)
            self.data_path.signal_latch_dr()

    def read_from_stack(self, directive):
        repeats = 1
        if directive == isa.InstructionPrefix.WORD:
            repeats = 2
        elif directive == isa.InstructionPrefix.DWORD:
            repeats = 4

        for i in range(repeats):
            if i > 0:
                # DR << 8 => DR
                self.data_path.alu.signal_set_dr_to_right()
                self.data_path.alu.signal_lshift_byte(left=False)
                self.data_path.signal_latch_dr()

            # SP => AR
            self.data_path.alu.signal_set_sp_to_right()
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_ar()

            # MEM[AR] => DR[7..0]
            self.data_path.signal_read()

            # SP + 1 => SP
            self.data_path.alu.signal_set_sp_to_right()
            self.data_path.alu.signal_inc(edit_flags=False, left=False)
            self.data_path.signal_latch_sp()

    def write_to_stack(self, directive):
        repeats = 1
        if directive == isa.InstructionPrefix.WORD:
            repeats = 2
        elif directive == isa.InstructionPrefix.DWORD:
            repeats = 4

        for i in range(repeats):
            # SP - 1 => SP, AR
            self.data_path.alu.signal_set_sp_to_right()
            self.data_path.alu.signal_dec(edit_flags=False, left=False)
            self.data_path.signal_latch_sp()
            self.data_path.signal_latch_ar()

            # DR[7..0] => MEM[AR]
            self.data_path.signal_write()

            # DR >> 8 => DR
            self.data_path.alu.signal_set_dr_to_right()
            self.data_path.alu.signal_rshift_byte(left=False)
            self.data_path.signal_latch_dr()

    def decode_prefix_and_opcode(self):
        """
        0 or IP => AR
        IP + 1 => IP
        MEM[AR] => DR[7..0]
        DR => CR
        if opcode == Prefix:
            CR[15..8], CR[7..0] => CR[7..0], CR[15..8]
            0 or IP => AR
            IP + 1 => IP
            MEM[AR] => DR[7..0]
            DR => CR
        """

        self.read_from_memory(isa.InstructionPrefix.BYTE)

        # DR => CR
        self.data_path.alu.signal_set_dr_to_right()
        self.data_path.alu.signal_or()
        self.data_path.signal_latch_cr()

        directive = isa.InstructionPrefix.WORD
        opcode = self.data_path.command_register.get() & 0xFF

        if (opcode == isa.InstructionPrefix.BYTE) or (opcode == isa.InstructionPrefix.WORD) or (
                opcode == isa.InstructionPrefix.DWORD):
            directive = opcode

            # DR << 8 => DR
            self.data_path.alu.signal_set_dr_to_right()
            self.data_path.alu.signal_lshift_byte(left=False)
            self.data_path.signal_latch_dr()

            self.read_from_memory(isa.InstructionPrefix.BYTE)

            # DR => CR
            self.data_path.alu.signal_set_dr_to_right()
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_cr()

            opcode = self.data_path.command_register.get() & 0xFF

        return directive, opcode

    def exec_no_args_instruction(self, opcode):
        """
        Выполнить инструкцию которая не требует аргумента
        """
        if opcode == isa.InstructionSet.HALT.opcode:
            self.data_path.signal_set_ps(w=0)
            raise StopIteration
        if opcode == isa.InstructionSet.NOP.opcode:
            pass
        elif opcode == isa.InstructionSet.CLC.opcode:
            self.data_path.signal_clear_carry()
        elif opcode == isa.InstructionSet.CMC.opcode:
            self.data_path.signal_invert_carry()
        elif opcode == isa.InstructionSet.EI.opcode:
            # 1 => PS(EI)
            self.data_path.signal_set_ps(ei=1)
        elif opcode == isa.InstructionSet.DI.opcode:
            # 0 => PS(EI)
            self.data_path.signal_set_ps(ei=0)
        elif opcode == isa.InstructionSet.RET.opcode:
            # MEM[SP] => DR
            self.read_from_stack(isa.InstructionPrefix.WORD)

            # DR => IP
            self.data_path.alu.signal_set_dr_to_right()
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_ip()

        elif opcode == isa.InstructionSet.IRET.opcode:
            # 0 => PS(I)
            self.data_path.program_state.set_i(0)

            # MEM[SP] => DR
            self.read_from_stack(isa.InstructionPrefix.WORD)

            # DR => IP
            self.data_path.alu.signal_set_dr_to_right()
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_ip()

    def decode_arg_prefix(self):
        """
        0 or IP => AR
        IP + 1 => IP
        MEM[AR] => DR[7..0]
        """
        self.read_from_memory(isa.InstructionPrefix.BYTE)

        return self.data_path.data_register.get_byte()

    def latch_register_by_code(self, register_code):
        # ALU => REG
        if register_code == isa.Registers.SP.code:
            self.data_path.signal_latch_sp()
        elif register_code == isa.Registers.R1.code:
            self.data_path.signal_latch_r1()
        elif register_code == isa.Registers.R2.code:
            self.data_path.signal_latch_r2()
        elif register_code == isa.Registers.R3.code:
            self.data_path.signal_latch_r3()
        elif register_code == isa.Registers.R4.code:
            self.data_path.signal_latch_r4()
        elif register_code == isa.Registers.R5.code:
            self.data_path.signal_latch_r5()
        elif register_code == isa.Registers.R6.code:
            self.data_path.signal_latch_r6()
        elif register_code == isa.Registers.R7.code:
            self.data_path.signal_latch_r7()

    def set_register_on_alu_by_code(self, register_code):
        # REG => ALU
        if register_code == isa.Registers.SP.code:
            self.data_path.alu.signal_set_sp_to_right()
        elif register_code == isa.Registers.R1.code:
            self.data_path.alu.signal_set_r1_to_left()
        elif register_code == isa.Registers.R2.code:
            self.data_path.alu.signal_set_r2_to_left()
        elif register_code == isa.Registers.R3.code:
            self.data_path.alu.signal_set_r3_to_left()
        elif register_code == isa.Registers.R4.code:
            self.data_path.alu.signal_set_r4_to_left()
        elif register_code == isa.Registers.R5.code:
            self.data_path.alu.signal_set_r5_to_right()
        elif register_code == isa.Registers.R6.code:
            self.data_path.alu.signal_set_r6_to_right()
        elif register_code == isa.Registers.R7.code:
            self.data_path.alu.signal_set_r7_to_right()

    def decode_instruction_arg_source(self, directive, to_ac=0, to_br=0, to_abr=0, sxt=0, pass_register=0,
                                      pass_memory_address=0):
        arg_type = self.decode_arg_prefix()
        arg_type_like = isa.InstructionPostfix.like_arg_type(arg_type)

        if arg_type_like == isa.InstructionPostfix.ArgIsImmediate:
            # значение идет дальше в памяти
            # 0 => DR
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_dr()

            self.read_from_memory(directive)

            # DR => ALU
            self.data_path.alu.signal_set_dr_to_right()
        elif arg_type_like == isa.InstructionPostfix.ArgIsRegister:
            if pass_register == 1:
                return arg_type, arg_type_like

            # значение - регистр
            register_code = isa.InstructionPostfix.decode_register(arg_type).code
            self.set_register_on_alu_by_code(register_code)
        elif arg_type_like == isa.InstructionPostfix.ArgsAreMemoryAddressing:
            # значение - адресация в память
            has_offset, has_index, scale_factor_power, offset_sign, index_sign = \
                isa.InstructionPostfix.decode_addressing_mode(arg_type)

            # Сохраняем scale factor в ABR3
            # DR[ScaleFactor] => 2 ^ sf => ABR3
            self.data_path.alu.signal_set_dr_to_right()
            self.data_path.alu.signal_decode_scale_factor(left=False)
            self.data_path.signal_latch_abr3()

            # Сохраняем base в ABR1
            self.decode_instruction_arg_source(isa.InstructionPrefix.WORD, to_abr=1)

            if has_index:
                # Сохраняем index в ABR2
                self.decode_instruction_arg_source(isa.InstructionPrefix.WORD, to_abr=2)

                # ABR2 * ABR3 => ABR2
                self.data_path.alu.signal_set_abr2_to_left()
                self.data_path.alu.signal_set_abr3_to_right()
                self.data_path.alu.signal_mul()
                self.data_path.signal_latch_abr3()

                # ABR1 + ABR3 => ABR1
                self.data_path.alu.signal_set_abr1_to_left()
                self.data_path.alu.signal_set_abr3_to_right()
                self.data_path.alu.signal_add(add_carry=False)
                self.data_path.signal_latch_abr1()

            if has_offset:
                # Сохраняем offset в ABR3
                self.decode_instruction_arg_source(isa.InstructionPrefix.WORD, to_abr=3)

                # ABR1 + ABR3 => ABR1
                self.data_path.alu.signal_set_abr1_to_left()
                self.data_path.alu.signal_set_abr3_to_right()
                self.data_path.alu.signal_add(add_carry=False)
                self.data_path.signal_latch_abr1()

            if pass_memory_address == 1:
                return arg_type, arg_type_like

            repeats = 1
            if directive == isa.InstructionPrefix.WORD:
                repeats = 2
            elif directive == isa.InstructionPrefix.DWORD:
                repeats = 4

            # 0 => DR
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_dr()

            for i in range(repeats):
                if i > 0:
                    # DR << 8 => DR
                    self.data_path.alu.signal_set_dr_to_right()
                    self.data_path.alu.signal_lshift_byte(left=False)
                    self.data_path.signal_latch_dr()

                # ABR1 => AR
                self.data_path.alu.signal_set_abr1_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_ar()

                # ABR1 + 1 => ABR1
                self.data_path.alu.signal_set_abr1_to_left()
                self.data_path.alu.signal_inc(edit_flags=False, left=True)
                self.data_path.signal_latch_abr1()

                # MEM[AR] => DR[7..0]
                self.data_path.signal_read()

            # Возращение значения ABR1 к началу данных
            # ABR1 - Bytes => ABR1
            for i in range(repeats):
                self.data_path.alu.signal_set_abr1_to_left()
                self.data_path.alu.signal_dec(edit_flags=False, left=True)
                self.data_path.signal_latch_abr1()

            # DR => ALU
            self.data_path.alu.signal_set_dr_to_right()

        if sxt == 1:
            # 1 => ALU(SXT)
            if directive == isa.InstructionPrefix.BYTE:
                self.data_path.alu.signal_sxt(is_byte=True)
            elif directive == isa.InstructionPrefix.WORD:
                self.data_path.alu.signal_sxt(is_byte=False)
            elif directive == isa.InstructionPrefix.DWORD:
                pass

        if to_ac == 1:
            # ALU => AC
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_ac()
        elif to_br == 1:
            # ALU => BR1
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_br1()
        elif to_br == 2:
            # ALU => BR2
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_br2()
        elif to_br == 3:
            # ALU => BR3
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_br3()
        elif to_abr == 1:
            # ALU => ABR1
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_abr1()
        elif to_abr == 2:
            # ALU => ABR2
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_abr2()
        elif to_abr == 3:
            # ALU => ABR3
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_abr3()

        return arg_type, arg_type_like

    def exec_one_arg_instruction(self, directive, opcode):
        destination_type, destination_type_like = 0, 0
        n = self.data_path.program_state.get_n()
        z = self.data_path.program_state.get_z()
        v = self.data_path.program_state.get_v()
        c = self.data_path.program_state.get_c()

        if opcode == isa.InstructionSet.NOT.opcode:
            destination_type, destination_type_like = self.decode_instruction_arg_source(directive)

            register_is_left = isa.InstructionPostfix.decode_register(destination_type).is_left

            # NOT(VAL) => ALU
            self.data_path.alu.signal_set_ac_to_left()
            self.data_path.alu.signal_not(left=register_is_left)

        elif opcode == isa.InstructionSet.NEG.opcode:
            destination_type, destination_type_like = self.decode_instruction_arg_source(directive, sxt=1)

            register_is_left = isa.InstructionPostfix.decode_register(destination_type).is_left

            # NEG(VAL) => ALU
            self.data_path.alu.signal_neg(left=register_is_left)

        elif opcode == isa.InstructionSet.INC.opcode:
            destination_type, destination_type_like = self.decode_instruction_arg_source(directive, sxt=1)

            register_is_left = isa.InstructionPostfix.decode_register(destination_type).is_left

            # INC(VAL) => ALU
            self.data_path.alu.signal_inc(edit_flags=True, left=register_is_left)

        elif opcode == isa.InstructionSet.DEC.opcode:
            destination_type, destination_type_like = self.decode_instruction_arg_source(directive, sxt=1)

            register_is_left = isa.InstructionPostfix.decode_register(destination_type).is_left

            # DEC(VAL) => ALU
            self.data_path.alu.signal_dec(edit_flags=True, left=register_is_left)

        elif opcode == isa.InstructionSet.SXT.opcode:
            destination_type, destination_type_like = self.decode_instruction_arg_source(directive)

            # SXT(AC) => ALU
            self.data_path.alu.signal_sxt(directive == isa.InstructionPrefix.BYTE)

        elif opcode == isa.InstructionSet.SWAB.opcode:
            destination_type, destination_type_like = self.decode_instruction_arg_source(directive)

            register_is_left = isa.InstructionPostfix.decode_register(destination_type).is_left

            # SXT(AC) => ALU
            self.data_path.alu.signal_swab(directive == isa.InstructionPrefix.WORD, left=register_is_left)

        elif opcode == isa.InstructionSet.JMP.opcode:
            self.decode_instruction_arg_source(directive, to_ac=1)

            self.data_path.alu.signal_set_ac_to_left()
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_ip()
            return
        elif opcode == isa.InstructionSet.JE.opcode:
            self.decode_instruction_arg_source(directive, to_ac=1)

            z = self.data_path.program_state.get_z()
            if z == 1:
                self.data_path.alu.signal_set_ac_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_ip()
            return
        elif opcode == isa.InstructionSet.JNE.opcode:
            self.decode_instruction_arg_source(directive, to_ac=1)

            if z == 0:
                self.data_path.alu.signal_set_ac_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_ip()
            return
        elif opcode == isa.InstructionSet.JG.opcode:
            self.decode_instruction_arg_source(directive, to_ac=1)

            if (n == v) and (z == 0):
                self.data_path.alu.signal_set_ac_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_ip()
            return
        elif opcode == isa.InstructionSet.JGE.opcode:
            self.decode_instruction_arg_source(directive, to_ac=1)

            if (n == v) or (z == 1):
                self.data_path.alu.signal_set_ac_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_ip()
            return
        elif opcode == isa.InstructionSet.JA.opcode:
            self.decode_instruction_arg_source(directive, to_ac=1)

            if (c == 0) and (z == 0):
                self.data_path.alu.signal_set_ac_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_ip()
            return
        elif opcode == isa.InstructionSet.JAE.opcode:
            self.decode_instruction_arg_source(directive, to_ac=1)

            if (c == 0) or (z == 1):
                self.data_path.alu.signal_set_ac_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_ip()
            return
        elif opcode == isa.InstructionSet.JL.opcode:
            self.decode_instruction_arg_source(directive, to_ac=1)

            if n != v:
                self.data_path.alu.signal_set_ac_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_ip()
            return
        elif opcode == isa.InstructionSet.JLE.opcode:
            self.decode_instruction_arg_source(directive, to_ac=1)

            if (n != v) or (z == 1):
                self.data_path.alu.signal_set_ac_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_ip()
            return
        elif opcode == isa.InstructionSet.JB.opcode:
            self.decode_instruction_arg_source(directive, to_ac=1)

            if c == 1:
                self.data_path.alu.signal_set_ac_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_ip()
            return
        elif opcode == isa.InstructionSet.JBE.opcode:
            self.decode_instruction_arg_source(directive, to_ac=1)

            if (c == 1) or (z == 1):
                self.data_path.alu.signal_set_ac_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_ip()
            return
        elif opcode == isa.InstructionSet.JS.opcode:
            self.decode_instruction_arg_source(directive, to_ac=1)

            if n == 1:
                self.data_path.alu.signal_set_ac_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_ip()
            return
        elif opcode == isa.InstructionSet.JNS.opcode:
            self.decode_instruction_arg_source(directive, to_ac=1)

            if n == 0:
                self.data_path.alu.signal_set_ac_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_ip()
            return
        elif opcode == isa.InstructionSet.JNC.opcode:
            self.decode_instruction_arg_source(directive, to_ac=1)

            if c == 0:
                self.data_path.alu.signal_set_ac_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_ip()
            return
        elif opcode == isa.InstructionSet.JV.opcode:
            self.decode_instruction_arg_source(directive, to_ac=1)

            if v == 1:
                self.data_path.alu.signal_set_ac_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_ip()
            return
        elif opcode == isa.InstructionSet.JNV.opcode:
            self.decode_instruction_arg_source(directive, to_ac=1)

            if v == 0:
                self.data_path.alu.signal_set_ac_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_ip()
            return
        elif opcode == isa.InstructionSet.LOOP.opcode:
            destination_type, destination_type_like = self.decode_instruction_arg_source(directive, to_ac=1)

            register_is_left = isa.InstructionPostfix.decode_register(destination_type).is_left

            self.data_path.alu.signal_dec(edit_flags=True, left=register_is_left)

            # записываем назад
            if destination_type_like == isa.InstructionPostfix.ArgIsRegister:
                register_code = isa.InstructionPostfix.decode_register(destination_type).code
                self.latch_register_by_code(register_code)
            elif destination_type_like == isa.InstructionPostfix.ArgsAreMemoryAddressing:
                # AC => DR
                self.data_path.signal_latch_dr()

                # ABR1 => DN
                self.data_path.alu.signal_set_abr1_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_dn()

                # DR => MEM[DN]
                self.write_to_memory(directive)

            # проверка и переход
            if (n == 1) or (z == 1):
                self.data_path.alu.signal_set_ip_to_right()
                self.data_path.alu.signal_inc(edit_flags=False, left=False)
                self.data_path.signal_latch_ip()
            return
        elif opcode == isa.InstructionSet.PUSH.opcode:
            self.decode_instruction_arg_source(directive)

            self.write_to_stack(directive)
            return
        elif opcode == isa.InstructionSet.POP.opcode:
            destination_type, destination_type_like = \
                self.decode_instruction_arg_source(directive, pass_register=1, pass_memory_address=1)

            # MEM[SP] => DR
            self.read_from_stack(directive)

            # SXT(DR) => ALU
            self.data_path.alu.signal_set_dr_to_right()
            self.data_path.alu.signal_sxt(directive == isa.InstructionPrefix.BYTE)
            self.data_path.alu.signal_or()

        elif opcode == isa.InstructionSet.CALL.opcode:
            self.decode_instruction_arg_source(isa.InstructionPrefix.WORD, to_ac=1)

            # IP => DR
            self.data_path.alu.signal_set_ip_to_right()
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_dr()

            # DR => MEM[SP]
            self.write_to_stack(isa.InstructionPrefix.WORD)

            # AC => IP
            self.data_path.alu.signal_set_ac_to_left()
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_ip()
            return
        elif opcode == isa.InstructionSet.INT.opcode:
            self.decode_instruction_arg_source(directive, to_ac=1)

            if self.data_path.program_state.get_ei() == 1:
                # 1 => PS(I)
                self.data_path.program_state.set_i(1)

                # IP => DR
                self.data_path.alu.signal_set_ip_to_right()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_dr()

                # MEM[SP] => DR
                self.write_to_stack(isa.InstructionPrefix.WORD)

                # AC << 1 => IP
                self.data_path.alu.signal_set_ac_to_left()
                self.data_path.alu.signal_asl(left=True)
                self.data_path.signal_latch_ip()

                # MEM[IP] => DR[15..0]
                self.read_from_memory(isa.InstructionPrefix.WORD)

                # DR => IP
                self.data_path.alu.signal_set_dr_to_right()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_ip()
            return

        if destination_type_like == isa.InstructionPostfix.ArgIsRegister:
            register_code = isa.InstructionPostfix.decode_register(destination_type).code
            # VAL => REG
            self.latch_register_by_code(register_code)
        elif destination_type_like == isa.InstructionPostfix.ArgsAreMemoryAddressing:
            # VAL => DR
            self.data_path.signal_latch_dr()

            # ABR1 => DN
            self.data_path.alu.signal_set_abr1_to_left()
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_dn()

            # DR => MEM[DN]
            self.write_to_memory(directive)

    def exec_two_args_instruction(self, directive, opcode):
        """
        AC, BR1 = значение, адрес аргумента 1
        BR2, BR3 = значение, адрес аргумента 2
        """

        def remember_first(destination_type_like):
            if destination_type_like == isa.InstructionPostfix.ArgsAreMemoryAddressing:
                # ABR1 => BR1
                self.data_path.alu.signal_set_abr1_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_br1()

        def remember_second(destination_type_like):
            if destination_type_like == isa.InstructionPostfix.ArgsAreMemoryAddressing:
                # ABR1 => BR3
                self.data_path.alu.signal_set_abr1_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_br3()

        destination_type1, destination_type_like1 = 0, 0

        if opcode == isa.InstructionSet.MOV.opcode:
            destination_type1, destination_type_like1 = \
                self.decode_instruction_arg_source(directive, pass_register=1, pass_memory_address=1)
            # ABR1 => BR1
            remember_first(destination_type_like1)

            self.decode_instruction_arg_source(directive, to_br=2)
            # BR2 => ALU
            self.data_path.alu.signal_set_br2_to_right()
            self.data_path.alu.signal_or()

        elif opcode == isa.InstructionSet.AND.opcode:
            destination_type1, destination_type_like1 = self.decode_instruction_arg_source(directive, to_ac=1)
            remember_first(destination_type_like1)

            self.decode_instruction_arg_source(directive, to_br=2)
            # AC AND BR2 => ALU
            self.data_path.alu.signal_set_ac_to_left()
            self.data_path.alu.signal_set_br2_to_right()
            self.data_path.alu.signal_and()
        elif opcode == isa.InstructionSet.OR.opcode:
            destination_type1, destination_type_like1 = self.decode_instruction_arg_source(directive, to_ac=1)
            remember_first(destination_type_like1)

            self.decode_instruction_arg_source(directive, to_br=2)
            # AC AND BR2 => ALU
            self.data_path.alu.signal_set_ac_to_left()
            self.data_path.alu.signal_set_br2_to_right()
            self.data_path.alu.signal_or()
        elif opcode == isa.InstructionSet.XOR.opcode:
            destination_type1, destination_type_like1 = self.decode_instruction_arg_source(directive, to_ac=1)
            remember_first(destination_type_like1)

            self.decode_instruction_arg_source(directive, to_br=2)
            # AC AND BR2 => ALU
            self.data_path.alu.signal_set_ac_to_left()
            self.data_path.alu.signal_set_br2_to_right()
            self.data_path.alu.signal_xor()
        elif (opcode == isa.InstructionSet.ADD.opcode) or (opcode == isa.InstructionSet.ADC.opcode):
            destination_type1, destination_type_like1 = self.decode_instruction_arg_source(directive, to_ac=1)
            remember_first(destination_type_like1)

            self.decode_instruction_arg_source(directive, to_br=2)
            # AC AND BR2 => ALU
            self.data_path.alu.signal_set_ac_to_left()
            self.data_path.alu.signal_set_br2_to_right()
            self.data_path.alu.signal_add(add_carry=opcode == isa.InstructionSet.ADC.opcode)
        elif opcode == isa.InstructionSet.SUB.opcode:
            destination_type1, destination_type_like1 = self.decode_instruction_arg_source(directive, to_ac=1)
            remember_first(destination_type_like1)

            self.decode_instruction_arg_source(directive, to_br=2)
            # AC AND BR2 => ALU
            self.data_path.alu.signal_set_ac_to_left()
            self.data_path.alu.signal_set_br2_to_right()
            self.data_path.alu.signal_sub()
        elif opcode == isa.InstructionSet.MUL.opcode:
            destination_type1, destination_type_like1 = self.decode_instruction_arg_source(directive, to_ac=1)
            remember_first(destination_type_like1)

            self.decode_instruction_arg_source(directive, to_br=2)
            # AC AND BR2 => ALU
            self.data_path.alu.signal_set_ac_to_left()
            self.data_path.alu.signal_set_br2_to_right()
            self.data_path.alu.signal_mul()
        elif opcode == isa.InstructionSet.DIV.opcode:
            destination_type1, destination_type_like1 = self.decode_instruction_arg_source(directive, to_ac=1)
            remember_first(destination_type_like1)

            self.decode_instruction_arg_source(directive, to_br=2)
            # AC AND BR2 => ALU
            self.data_path.alu.signal_set_ac_to_left()
            self.data_path.alu.signal_set_br2_to_right()
            self.data_path.alu.signal_div()
        elif opcode == isa.InstructionSet.MOD.opcode:
            destination_type1, destination_type_like1 = self.decode_instruction_arg_source(directive, to_ac=1)
            remember_first(destination_type_like1)

            self.decode_instruction_arg_source(directive, to_br=2)
            # AC AND BR2 => ALU
            self.data_path.alu.signal_set_ac_to_left()
            self.data_path.alu.signal_set_br2_to_right()
            self.data_path.alu.signal_mod()
        elif opcode == isa.InstructionSet.CMP.opcode:
            self.decode_instruction_arg_source(directive, to_ac=1)
            self.decode_instruction_arg_source(directive, to_br=2)
            # AC AND BR2 => ALU
            self.data_path.alu.signal_set_ac_to_left()
            self.data_path.alu.signal_set_br2_to_right()
            self.data_path.alu.signal_sub()
            self.data_path.signal_latch_ac()
            return
        elif opcode == isa.InstructionSet.SWAP.opcode:
            destination_type1, destination_type_like1 = self.decode_instruction_arg_source(directive, to_ac=1)
            remember_first(destination_type_like1)

            destination_type2, destination_type_like2 = self.decode_instruction_arg_source(directive, to_br=2)
            remember_second(destination_type_like2)

            # AC => DR
            self.data_path.alu.signal_set_ac_to_left()
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_dr()

            if destination_type_like2 == isa.InstructionPostfix.ArgIsRegister:
                register_code = isa.InstructionPostfix.decode_register(destination_type1).code
                # VAL => REG
                self.latch_register_by_code(register_code)
            elif destination_type_like2 == isa.InstructionPostfix.ArgsAreMemoryAddressing:
                # VAL => DR
                self.data_path.signal_latch_dr()

                # BR3 => DN
                self.data_path.alu.signal_set_br3_to_right()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_dn()

                # DR => MEM[DN]
                self.write_to_memory(directive)

            # BR2
            self.data_path.alu.signal_set_br2_to_right()
            self.data_path.alu.signal_or()

        if destination_type_like1 == isa.InstructionPostfix.ArgIsRegister:
            register_code = isa.InstructionPostfix.decode_register(destination_type1).code
            # VAL => REG
            self.latch_register_by_code(register_code)
        elif destination_type_like1 == isa.InstructionPostfix.ArgsAreMemoryAddressing:
            # VAL => DR
            self.data_path.signal_latch_dr()

            # BR1 => DN
            self.data_path.alu.signal_set_br1_to_left()
            self.data_path.alu.signal_or()
            self.data_path.signal_latch_dn()

            # DR => MEM[DN]
            self.write_to_memory(directive)

    def exec_var_args_instruction(self, directive, opcode):
        # 0 => DR
        self.data_path.alu.signal_or()
        self.data_path.signal_latch_dr()

        self.read_from_memory(isa.InstructionPrefix.BYTE)

        # DR => BR3
        self.data_path.alu.signal_set_dr_to_right()
        self.data_path.alu.signal_add(add_carry=False)
        self.data_path.signal_latch_br3()

        if (self.data_path.program_state.get_z() == 1) or (self.data_path.program_state.get_n() == 1):
            raise Exceptions.VarArgsCountError(self.data_path.data_register.get())

        if opcode == isa.InstructionSet.LCOMB.opcode:
            # запоминаем первый аргумент (значение, и туда будем записывать)
            destination_type, destination_type_like = self.decode_instruction_arg_source(directive, to_ac=1)

            if destination_type_like == isa.InstructionPostfix.ArgsAreMemoryAddressing:
                # ABR1 => DN
                self.data_path.alu.signal_set_abr1_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_dn()

            # BR3 - 1 => BR3
            self.data_path.alu.signal_set_br3_to_right()
            self.data_path.alu.signal_dec(edit_flags=True, left=False)
            self.data_path.signal_latch_br3()

            while self.data_path.program_state.get_z() == 0:
                # ARG => BR1
                self.decode_instruction_arg_source(directive, to_br=1)

                # ARG => BR2
                self.decode_instruction_arg_source(directive, to_br=2)

                # BR1 * BR2 => BR2
                self.data_path.alu.signal_set_br1_to_left()
                self.data_path.alu.signal_set_br2_to_right()
                self.data_path.alu.signal_mul()
                self.data_path.signal_latch_br2()

                # AC + BR2 => AC
                self.data_path.alu.signal_set_ac_to_left()
                self.data_path.alu.signal_set_br2_to_right()
                self.data_path.alu.signal_add(add_carry=False)
                self.data_path.signal_latch_ac()

                # BR3 - 1, N, Z, V, C => BR3, N, Z, V, C
                self.data_path.alu.signal_set_br3_to_right()
                self.data_path.alu.signal_dec(edit_flags=True, left=False)
                self.data_path.signal_latch_br3()

                # BR3 - 1, N, Z, V, C => BR3, N, Z, V, C
                self.data_path.alu.signal_set_br3_to_right()
                self.data_path.alu.signal_dec(edit_flags=True, left=False)
                self.data_path.signal_latch_br3()

            if destination_type_like == isa.InstructionPostfix.ArgIsRegister:
                # получатель - регистр
                register_code = isa.InstructionPostfix.decode_register(destination_type).code

                # AC => ALU
                self.data_path.alu.signal_set_ac_to_left()
                self.data_path.alu.signal_or()
                # ALU => REG
                self.latch_register_by_code(register_code)
            elif destination_type_like == isa.InstructionPostfix.ArgsAreMemoryAddressing:
                # получатель - память

                # AC => DR
                self.data_path.alu.signal_set_ac_to_left()
                self.data_path.alu.signal_or()
                self.data_path.signal_latch_dr()

                # DR => MEM[DN]
                self.write_to_memory(directive)

    def decode_and_execute_instruction(self):
        """Основной цикл процессора. Декодирует и выполняет инструкцию.

        Обработка инструкции:

        - Проверить `директиву` и `Opcode`.

        - Вызвать методы, имитирующие необходимые управляющие сигналы.

        - Продвинуть модельное время вперёд на одну инструкцию.

        - Перейти к следующей инструкции.

        Обработка функций управления потоком исполнения вынесена в
        `decode_and_execute_control_flow_instruction`.
        """

        directive, opcode = self.decode_prefix_and_opcode()
        instruction = isa.InstructionSet.opcode_to_instruction(opcode)
        args_count = len(instruction.args_types)
        variable_args_count = instruction.variable_args_count

        if variable_args_count:
            self.exec_var_args_instruction(directive, opcode)
        elif args_count == 0:
            self.exec_no_args_instruction(opcode)
        elif args_count == 1:
            self.exec_one_arg_instruction(directive, opcode)
        elif args_count == 2:
            self.exec_two_args_instruction(directive, opcode)

    def instruction_tick_gen(self):
        self.decode_and_execute_instruction()
        self.instruction_tick()

    def __repr__(self):
        """Вернуть строковое представление состояния процессора."""

        def to_hex(value: int, byte_size: int):
            string = hex(value)
            additional = (byte_size * 2) - (len(string) - 2)
            string = ("0" * additional) + string[2:]

            return " ".join([string[i:i + 2] for i in range(0, len(string), 2)])

        def ps_to_str(ps: isa.ProgramStateRegister):
            highlight = "*"
            default = "_"

            flags = [
                (ps.get_w() == 1, "w"),
                (ps.get_i() == 1, "i"),
                (ps.get_ei() == 1, "e"),
                (ps.get_n() == 1, "n"),
                (ps.get_z() == 1, "z"),
                (ps.get_v() == 1, "v"),
                (ps.get_c() == 1, "c"),
            ]

            subs = []
            for i, pair in enumerate(flags):
                flag, char = pair
                if flag:
                    subs.append("{}{}{}".format(highlight, char.upper(), highlight))
                else:
                    subs.append("{}{}{}".format(default, char.lower(), default))

            return " ".join(subs)

        opcode = self.data_path.command_register.get() & 0xFF

        state_repr = [
            "TICK: {:8}".format(self._instruction_tick),
            "PS: {}".format(ps_to_str(self.data_path.program_state)),
            "IP: {}".format(to_hex(self.data_path.instruction_pointer.get(), 2)),
            "AR: {}".format(to_hex(self.data_path.address_register.get(), 2)),
            "MEM[AR]: {}".format(to_hex(self.data_path.memory[self.data_path.address_register.get()], 1)),
            "DR: {}".format(to_hex(self.data_path.data_register.get(), 4)),
            "AC: {}".format(to_hex(self.data_path.ac.get(), 4)),
            "BR1: {}".format(to_hex(self.data_path.buffer_register1.get(), 4)),
            "BR2: {}".format(to_hex(self.data_path.buffer_register2.get(), 4)),
            "BR3: {}".format(to_hex(self.data_path.buffer_register3.get(), 4)),
            "CR: {}".format(to_hex(self.data_path.command_register.get(), 2)),
            "DN: {}".format(to_hex(self.data_path.destination_register.get(), 2)),
            "ABR1: {}".format(to_hex(self.data_path.address_buffer_register1.get(), 2)),
            "ABR2: {}".format(to_hex(self.data_path.address_buffer_register2.get(), 2)),
            "ABR3: {}".format(to_hex(self.data_path.address_buffer_register3.get(), 2)),
            "SP: {}".format(to_hex(self.data_path.stack_pointer.get(), 2)),
            "MEM[SP]: {}".format(to_hex(self.data_path.memory[self.data_path.stack_pointer.get()], 1)),
            "R1: {}".format(to_hex(self.data_path.r1.get(), 4)),
            "R2: {}".format(to_hex(self.data_path.r2.get(), 4)),
            "R3: {}".format(to_hex(self.data_path.r3.get(), 4)),
            "R4: {}".format(to_hex(self.data_path.r4.get(), 4)),
            "R5: {}".format(to_hex(self.data_path.r5.get(), 4)),
            "R6: {}".format(to_hex(self.data_path.r6.get(), 4)),
            "R7: {}".format(to_hex(self.data_path.r7.get(), 4)),
            "Mnemonic: {}".format(translator.Parser.opcode_to_mnemonic(opcode))
        ]

        return " | ".join(state_repr)


def simulation(start_address: int, code: list, input_schedule: list, limit: int):
    """Подготовка модели и запуск симуляции процессора.

    Длительность моделирования ограничена:

    - количеством выполненных инструкций (`limit`);

    - количеством данных ввода (`input_tokens`, если ввод используется), через
      исключение `EOFError`;

    - инструкцией `Halt`, через исключение `StopIteration`.
    """

    input_device = InputDevice(input_schedule)
    output_device = OutputDevice()

    data_path = DataPath(start_address, code, input_device, output_device)
    control_unit = ControlUnit(data_path)
    instr_counter = 0

    def devices_live():
        input_device.live()
        output_device.live()

    try:
        while instr_counter < limit:
            logging.debug("%s", control_unit)
            control_unit.instruction_tick_gen()
            instr_counter += 1

            devices_live()
    except StopIteration:
        logging.info("Машина остановилась")
    except Exception as e:
        logging.warning("{}".format(e))

    if instr_counter >= limit:
        logging.warning("Предел превышен")

    output = "".join([chr(char) for char in output_device.get_buffer()])

    return output, instr_counter


class InputScheduler:
    number_regex = re.compile(r"(\d+)")
    tuple_regex = re.compile(r"\((\d+),\s*\'([^\']|\d{,3})\'\)")

    @staticmethod
    def make_from(text: str):
        match = InputScheduler.tuple_regex.findall(text)

        if match is None:
            return []

        return [(int(time), ord(char)) for time, char in match]


def main(code_file, input_file):
    """
    Функция запуска модели процессора. Параметры -- имена файлов с машинным
    кодом и с расписанием входных данных для симуляции.
    """
    start_address, code = isa.ByteCodeFile.read_code(code_file)

    with open(input_file, encoding="utf-8") as file:
        input_text = file.read()
        input_schedule = InputScheduler.make_from(input_text)

    if len(input_schedule) == 0:
        input_schedule = [(0, 0)]

    output, instr_counter = simulation(
        start_address,
        code,
        input_schedule=input_schedule,
        limit=600,
    )

    print("Output: {}".format(output))
    print("instr_counter: {}".format(instr_counter))


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    assert len(sys.argv) == 3, "Wrong arguments: p_machine.py <code_file> <input_file>"
    _, v1, v2 = sys.argv

    main(v1, v2)

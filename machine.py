import logging

from isa import ByteCodeFile


def simulation(code, input_schedule, memory_size=0xFFFF, limit=1000):
    """

    """

    return [], 0, 0


def main(code_file, input_file):
    """
    Функция запуска модели процессора. Параметры -- имена файлов с машинным
    кодом и с расписанием входных данных для симуляции.
    """
    code = ByteCodeFile.read_code(code_file)
    with open(input_file, encoding="utf-8") as file:
        input_text = file.read()
        input_token = []
        for char in input_text:
            input_token.append(char)

    output, instr_counter, ticks = simulation(
        code,
        input_schedule=input_token,
        memory_size=100,
        limit=1000,
    )

    print("".join(output))
    print("instr_counter: ", instr_counter, "ticks:", ticks)


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    # assert len(sys.argv) == 3, "Wrong arguments: p_machine.py <code_file> <input_file>"
    # _, code_file, input_file = sys.argv
    _, code_file, input_file = "", "./target/simple.o", "./output/simple.out"
    main(code_file, input_file)

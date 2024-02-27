import re

org_directive_regex = re.compile(r"org *(0x[\da-f]+|\d+)")
var_define_regex = re.compile(r"([_\.a-z][_\.\da-z]*:)? *(byte |word ) *(0x[\da-f]+|\d+|\'[^']+\'|[_\.a-z][_\.\da-z]*)")
instruction_regex = re.compile(
    r"([_a-z]\w*:)? *([a-z]+) +(byte |word )? *([_\.a-z0-9]+|\[[^\[\]]+\])( *, *(byte |word )? *([_\.a-z0-9]+|\[[^\[\]]+\]))*")

# s = "lal:         st   byte rax  ,    word [sp+    5 ],    rax"
s = "word _int1, 0x160"


class Parser:
    directives = ["byte", "word"]
    number_regex = re.compile(r"(0x[\da-f]+|\d+)")
    string_regex = re.compile(r"(\'[^\']+\')")
    label_name_regex = re.compile(r"([_\.a-z][_\.\da-z]*)")

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
    def try_find_label_with_colon(line: str):
        label_name, line = Parser.try_find_label_name(line)

        if len(line) == 0 or line[0] != ":":
            raise Exception("Метка должна кончаться на `:`")

        return label_name + ":", line[1:].lstrip(" ")

    @staticmethod
    def try_find_directive(line: str):
        line = line.lstrip(" ")

        pos = line.find(" ")
        directive = line[:pos]

        if directive not in Parser.directives:
            raise Exception("`{}` - не директива, можно так = {}".format(directive, Parser.directives))

        return directive, line[pos:].lstrip(" ")

    @staticmethod
    def try_find_number(line: str):
        line = line.lstrip(" ")

        match = Parser.number_regex.match(line)

        if match is None:
            raise Exception("`{}` - не число, можно так = [0x0123456789ABCDEF, 0123456789]".format(line))

        return match.group(1), line[match.end(1):].lstrip(" ")

    @staticmethod
    def try_find_string(line: str):
        line = line.lstrip(" ")

        match = Parser.string_regex.match(line)

        if match is None:
            raise Exception("`{}` - не строка, можно так = r\"'[^\']+'\"".format(line))

        return match.group(1), line[match.end(1):].lstrip(" ")

    @staticmethod
    def try_find_args(line: str):
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

        line = line.lstrip(" ")

        if len(line) > 0:
            if line[0] == ",":
                new_args, line = Parser.try_find_args(line[1:])
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

        args, line = Parser.try_find_args(line)
        line = line.lstrip(" ")

        if line[0] != ")":
            raise Exception("После аргументов ожидалось `)`")

        if number.find("0x") >= 0:
            number = int(number, 16)
        else:
            number = int(number)

        return args * number, line[1:]

    @staticmethod
    def parse_var_def(line):
        try:
            label, line = Parser.try_find_label_with_colon(line)
        except Exception as e:
            label = None
            pass

        directive, line = Parser.try_find_directive(line)
        args, line = Parser.try_find_args(line)

        return label, directive, args


print(", ".join(["as", "we"]))

exit(0)

regex = re.compile(instruction_regex)
match = regex.match(s)

print([s.strip(" ") for s in (match.string[match.end(2):]).split(",")])

# Отчёт

- P33151, Шипулин Павел Андреевич.
- `asm | cisc | neum | hw | instr | binary | trap | mem | cstr | prob2 | spi`
- без усложнения

## Язык программирования

###Описание синтаксиса
Надо бы еще секции (`<section>`) подкорректировать, в интернете написано, что там разные секции есть...
``` ebnf
<asm_program> ::= 
    <spaces> | 
    <new_line> | 
    <section> <empty_string> | 
    <variable> <empty_string> | 
    <instruction> <empty_string> | 
    <asm_program> <asm_program>

<empty_string> ::= <new_line> | <spaces> <empty_string>

<section> ::= "section" <spaces> "." <section_without_prefix>
<section_without_prefix> ::= "data" | "text"

<instruction> ::= 
    <instruction_label> | 
    <mnemonic> | 
    <instruction_label> <spaces> <mnemonic> | 
    <mnemonic> <spaces> <operands> | 
    <instruction_label> <spaces> <mnemonic> <spaces> <operands> | 
    <instruction> <spaces> <comment> | 
    <spaces> <instruction> 

<mnemonic> ::= "ВСЕ КОМАНДЫ СЮДА ВПИСАТЬ"
<comment> ::= ";" <characters>

<operands> ::= <operand> | <operands> <listing_separator> <operand>
<operand> ::= <register> | <mem_addressing> | <math_expression> | <complex_label>

<mem_addressing> ::= "[" <math_expression> "]" | "~[" <math_expression> "]"

<math_expression> ::= 
    <register> | 
    <number> | 
    <spaces> <math_expression> | 
    <math_expression> <spaces> | 
    <math_expression> <math_operation> <math_expression> | 
    "(" <math_expression> ")"

<math_operation> ::= "+" | "-" | "*" | "/"

<variable> ::= <data_label> <spaces> <data_pseudo_command>
<data_pseudo_command> ::= 
    <reserve> | 
    <define> | 
    "times" <spaces> <uint> <spaces> <data_pseudo_command>

<define> ::= <define_command> <spaces> <array_init>
<define_command> ::= "db" | "dw" | "dd"

<reserve> ::= <reserve_command> <spaces> <uint>
<reserve_command> ::= "resb" | "resw" | "resd"

<array_init> ::= 
    <int_sequence> | 
    <double_sequence> | 
    <string_sequence> | 
    <array_init> <listing_separator> <int_sequence> | 
    <array_init> <listing_separator> <string_sequence>

<int_sequence> ::= <int> | <int_sequence> <listing_separator> <int>
<double_sequence> ::= <double> | <double_sequence> <listing_separator> <double>
<string_sequence> ::= <string> | <string_sequence> <listing_separator> <string>
<listing_separator> ::= "," | <spaces> "," | "," <spaces> | <spaces> "," <spaces>

<data_label> ::= <name_word> | <instruction_label>
<instruction_label> ::= <complex_label> ":"

<complex_label> ::= <single_label> | <relative_label> | <complex_label> <relative_label>
<relative_label> ::= "." <single_label>
<single_label> ::= <name_word> | "_" <name_word>

<register> ::= 
    "rpc" | "rdi" | "rsi" | "rax" | 
    "rcx" | "rdx" | "rsp" | "r1" | 
    "r2" | "r3" | "r4" | "r5" | 
    "r6" | "r7" | "r8"

<string> ::= 
    <special_quote> <string_without_special_quote> <special_quote> | 
    <single_quote> <string_without_single_quote> <single_quote> | 
    <double_quote> <string_without_double_quote> <double_quote>

<string_without_special_quote> ::= 
    <character> | 
    <double_quote> | 
    <single_quote> | 
    <string_without_special_quote> <string_without_special_quote>

<string_without_double_quote> ::= 
    <character> | 
    <special_quote> | 
    <single_quote> | 
    <string_without_double_quote> <string_without_double_quote>

<string_without_single_quote> ::= 
    <character> |  
    <special_quote> | 
    <double_quote> | 
    <string_without_single_quote> <string_without_single_quote>

<special_quote> ::= "`"
<double_quote> ::= "\""
<single_quote> ::= "'"
<special_char> ::= <backslash> <letter>
<char_by_dec_uint> ::= <backslash> <dec_uint>

<name_word> ::= <letter> | <letter> <name_word> | <name_word> <letter> | <name_word> <dec_digit>
<characters> ::= <character> | <characters> <character>
<character> ::= <letter> | <dec_digit> | <symbol>
<symbol> ::= 
    <space> | <backslash> | "!" | 
    "@" | "#" | "$" | "%" | 
    "^" | "&" | "*" | "-" | 
    "+" | "," | "." | ";" | 
    ":" | "?" | "_" | "=" | 
    "(" | ")" | "[" | "]" | 
    "{" | "}" | "|" | "/"

<spaces> ::= <space> | <spaces> <space>
<space> ::= " " | "\t"

<new_line> ::= "\n"

<backslash> ::= "\\"
<letter> ::= 
    "A" | "B" | "C" | "D" | "E" | "F" | 
    "G" | "H" | "I" | "J" | "K" | "L" | 
    "M" | "N" | "O" | "P" | "Q" | "R" | 
    "S" | "T" | "U" | "V" | "W" | "X" | 
    "Y" | "Z" | "a" | "b" | "c" | "d" | 
    "e" | "f" | "g" | "h" | "i" | "j" | 
    "k" | "l" | "m" | "n" | "o" | "p" | 
    "q" | "r" | "s" | "t" | "u" | "v" | 
    "w" | "x" | "y" | "z"

<number> ::= <int> | <double>
<int> ::= <bin_int> | <dec_int> | <hex_int>
<uint> ::= <bin_uint> | <dec_uint> | <hex_uint>

<hex_int> ::= <hex_uint> | "-" <hex_uint>
<hex_uint> ::= "0x" <hex_uint_without_prefix> 
<hex_uint_without_prefix> ::= <hex_digit> | <hex_digit> <hex_uint_without_prefix>
<hex_digit> ::= "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "A" | "B" | "C" | "D" | "E" | "F" | "a" | "b" | "c" | "d" | "e" | "f"

<double> ::= <dec_digit> "." <dec_uint> "e" <dec_int> | "-" <dec_digit> "." <dec_uint> "e" <dec_int>
<dec_int> ::= <dec_uint> | "-" <dec_uint>
<dec_uint> ::= <dec_digit> | <dec_digit> <dec_uint>
<dec_digit> ::= "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"

<bin_int> ::= <bin_uint> | "-" <bin_uint>
<bin_uint> ::= "b" <bin_uint_without_prefix>
<bin_uint_without_prefix> ::= <bin_digit> | <bin_digit> <bin_uint_without_prefix>
<bin_digit> ::= "0" | "1"
```

### Описание семантики

Код выполняется с метки `start`, так что её присутствие обязательно для запуска программы.

- перечисление всех команд, ключевых слов видимо... 

Любые символы после `;` трактуются как комментарий в строке (многострочных комментариев нет)

Память выделяется в соответствии с указанными в коде директивами `org`:

- `org <число>` -- разместить следующий байт-код по этом адресу

или "локально" с помощью команд для работы со стеком:
- `push <регистр / память / литерал>` -- добавляет на стек значение выражения, смещает стековый указатель
- `pop <регистр / память>` -- возвращает значение со стека, смещает указатель на стек

Литералы:
- целое число
  - десятичный (`009128738912`)
  - шестнадцатеричный (`0x0000000012312312332312323`)
- строка
  - `<строка>`
  - (слово)

## Организация памяти

Модель памяти процессора (приведено списком, так как тривиальна):

1. Память команд. Машинное слово -- не определено. Реализуется списком словарей, описывающих инструкции (одно слово -- одна ячейка).
2. Память данных. Машинное слово -- 8 бит, знаковое. Линейное адресное пространство. Реализуется списком чисел.

В связи с отсутствием на уровне языка переменных, констант, литералов и т.д., описание механизмов работы с ними -- отсутствует. Содержание раздела -- смотри в задании.

Данный раздел является сквозным по отношению к работе и должен включать:
- модель памяти процессора, размеры машинного слова, варианты адресации;
- механику отображения программы и данных на процессор.

Модель памяти должна включать:
- Какие виды памяти и регистров доступны программисту?
- Где хранятся инструкции, процедуры и прерывания?
- Где хранятся статические и динамические данные?

А также данный раздел должен включать в себя описание того, как происходит работа с 1) литералами, 2) константами, 3) переменными, 4) инструкциями, 5) процедурами, 6) прерываниями во время компиляции и исполнения. К примеру:

В каких случаях литерал будет использован при помощи непосредственной адресации?
В каких случаях литерал будет сохранён в статическую память?
Как будут размещены литералы, сохранённые в статическую память, друг относительно друга?
Как будет размещаться в память литерал, требующий для хранения несколько машинных слов?
В каких случаях переменная будет отображена на регистр?
Как будет разрешаться ситуация, если регистров недостаточно для отображения всех переменных?
В каких случаях переменная будет отображена на статическую память?
В каких случаях переменная будет отображена на стек?
И так далее по каждому из пунктов в зависимости от варианта...

## Система команд

Особенности процессора:

- Машинное слово -- 8 бит, знаковое.
- Доступ к памяти данных осуществляется по адресу, хранимому в специальном регистре `data_address`. Установка адреса осуществляется путём инкрементирования или декрементирования инструкциями `<` и `>`.
- Обработка данных осуществляется по текущему адресу операциями `+` и `-`, а также через ввод/вывод.
- Поток управления:
    - инкремент `PC` после каждой инструкции;
    - условный (`jz`) и безусловный (`jmp`) переходы (использование см. в разделе транслятор).

### Набор инструкций

| Язык | Инструкция   | Кол-во тактов | Описание                                                    |
|:-----|:-------------|:--------------|:------------------------------------------------------------|
| `+`  | increment    | 2             | увеличить значение в текущей ячейке на 1                    |
| `-`  | decrement    | 2             | уменьшить значение в текущей ячейке на 1                    |
| `<`  | left         | 1             | перейти к следующей ячейке                                  |
| `>`  | right        | 1             | перейти к предыдущей ячейке                                 |
| `.`  | print        | 2             | напечатать значение из текущей ячейки (символ)              |
| `,`  | input        | 2             | ввести извне значение и сохранить в текущей ячейке (символ) |
|      | jmp `<addr>` | 1             | безусловный переход                                         |
|      | jz `<addr>`  | 2             | переход, если в текущей ячейке 0                            |
|      | halt         | 0             | остановка                                                   |

- `<addr>` -- исключительно непосредственная адресация памяти команд.

### Кодирование инструкций

- Машинный код сериализуется в список JSON.
- Один элемент списка -- одна инструкция.
- Индекс списка -- адрес инструкции. Используется для команд перехода.

Пример:

```json
[
    {
        "opcode": "jz",
        "arg": 5,
        "term": [
            1,
            5,
            "]"
        ]
    }
]
```

где:

- `opcode` -- строка с кодом операции;
- `arg` -- аргумент (может отсутствовать);
- `term` -- информация о связанном месте в исходном коде (если есть).

Типы данных в модуле [isa](p_isa.py), где:

- `Opcode` -- перечисление кодов операций;
- `Term` -- структура для описания значимого фрагмента кода исходной программы.

## Транслятор

Интерфейс командной строки: `translator.py <input_file> <target_file>`

Реализовано в модуле: [translator](p_translator.py)

Этапы трансляции (функция `translate`):

1. Трансформирование текста в последовательность значимых термов.
2. Проверка корректности программы (парность квадратных скобок).
3. Генерация машинного кода.

Правила генерации машинного кода:

- один символ языка -- одна инструкция;
- для команд, однозначно соответствующих инструкциям, -- прямое отображение;
- для циклов с соблюдением парности (многоточие -- произвольный код):

    | Номер команды/инструкции | Программа | Машинный код |
    |:-------------------------|:----------|:-------------|
    | n                        | `[`       | `JZ (k+1)`   |
    | ...                      | ...       | ...          |
    | k                        | `]`       | `JMP n`      |
    | k+1                      | ...       | ...          |

Примечание: вопросы отображения переменных на регистры опущены из-за отсутствия оных.

## Модель процессора

Интерфейс командной строки: `machine.py <machine_code_file> <input_file>`

Реализовано в модуле: [machine](p_machine.py).

### DataPath

``` text
     latch --------->+--------------+  addr   +--------+
     data            | data_address |---+---->|  data  |
     addr      +---->+--------------+   |     | memory |
               |                        |     |        |
           +-------+                    |     |        |
    sel -->|  MUX  |         +----------+     |        |
           +-------+         |                |        |
            ^     ^          |                |        |
            |     |          |       data_in  |        | data_out
            |     +---(+1)---+          +---->|        |-----+
            |                |          |     |        |     |
            +---------(-1)---+          |  oe |        |     |
                                        | --->|        |     |
                                        |     |        |     |
                                        |  wr |        |     |
                                        | --->|        |     |
                                        |     +--------+     |
                                        |                    v
                                    +--------+  latch_acc +-----+
                          sel ----> |  MUX   |  --------->| acc |
                                    +--------+            +-----+
                                     ^   ^  ^                |
                                     |   |  |                +---(==0)---> zero
                                     |   |  |                |
                                     |   |  +---(+1)---------+
                                     |   |                   |
                                     |   +------(-1)---------+
                                     |                       |
            input -------------------+                       +---------> output
```

Реализован в классе `DataPath`.

`data_memory` -- однопортовая память, поэтому либо читаем, либо пишем.

Сигналы (обрабатываются за один такт, реализованы в виде методов класса):

- `latch_data_addr` -- защёлкнуть выбранное значение в `data_addr`;
- `latch_acc` -- защёлкнуть в аккумулятор выход памяти данных;
- `wr` -- записать выбранное значение в память:
    - инкрементированное;
    - декрементированное;
    - с порта ввода `input` (обработка на Python):
        - извлечь из входного буфера значение и записать в память;
        - если буфер пуст -- выбросить исключение;
- `output` -- записать аккумулятор в порт вывода (обработка на Python).

Флаги:

- `zero` -- отражает наличие нулевого значения в аккумуляторе.

### ControlUnit

``` text
   +------------------(+1)-------+
   |                             |
   |    latch_program_counter    |
   |                  |          |
   |   +-----+        v          |
   +-->|     |     +---------+   |    +---------+
       | MUX |---->| program |---+--->| program |
   +-->|     |     | counter |        | memory  |
   |   +-----+     +---------+        +---------+
   |      ^                               |
   |      | sel_next                      | current instruction
   |      |                               |
   +---------------(select-arg)-----------+
          |                               |      +---------+
          |                               |      |  step   |
          |                               |  +---| counter |
          |                               |  |   +---------+
          |                               v  v        ^
          |                       +-------------+     |
          +-----------------------| instruction |-----+
                                  |   decoder   |
                                  |             |<-------+
                                  +-------------+        |
                                          |              |
                                          | signals      |
                                          v              |
                                    +----------+  zero   |
                                    |          |---------+
                                    | DataPath |
                     input -------->|          |----------> output
                                    +----------+
```

Реализован в классе `ControlUnit`.

- Hardwired (реализовано полностью на Python).
- Метод `decode_and_execute_instruction` моделирует выполнение полного цикла инструкции (1-2 такта процессора).
- `step_counter` необходим для многотактовых инструкций;
    - в реализации класс `ControlUnit` отсутствует, т.к. неявно задан потоком управления.

Сигнал:

- `latch_program_counter` -- сигнал для обновления счётчика команд в ControlUnit.

Особенности работы модели:

- Цикл симуляции осуществляется в функции `simulation`.
- Шаг моделирования соответствует одной инструкции с выводом состояния в журнал.
- Для журнала состояний процессора используется стандартный модуль `logging`.
- Количество инструкций для моделирования лимитировано.
- Остановка моделирования осуществляется при:
    - превышении лимита количества выполняемых инструкций;
    - исключении `EOFError` -- если нет данных для чтения из порта ввода;
    - исключении `StopIteration` -- если выполнена инструкция `halt`.

## Тестирование

В качестве тестов использовано два алгоритма (в задании 3 + алгоритм по варианту):

1. [hello world](p_examples/hello.bf).
2. [cat](p_examples/cat.bf) -- программа `cat`, повторяем ввод на выводе.

Интеграционные тесты реализованы тут [integration_test](p_integration_test.py) в двух вариантах:

- через golden tests, конфигурация которых лежит в папке [golden](./golden) (требуются по заданию).
- через unittest (приведён как **устаревший** пример).

CI:

``` yaml
lab3-example:
  stage: test
  image:
    name: ryukzak/python-tools
    entrypoint: [""]
  script:
    - cd src/brainfuck
    - poetry install
    - coverage run -m pytest --verbose
    - find . -type f -name "*.py" | xargs -t coverage report
    - ruff format --check .
    - ruff check .
```

где:

- `ryukzak/python-tools` -- docker образ, который содержит все необходимые для проверки утилиты. Подробнее: [Dockerfile](/src/Dockerfiles/python-tools.Dockerfile)
- `poetry` -- управления зависимостями для языка программирования Python.
- `coverage` -- формирование отчёта об уровне покрытия исходного кода.
- `pytest` -- утилита для запуска тестов.
- `ruff` -- утилита для форматирования и проверки стиля кодирования.

Пример использования и журнал работы процессора на примере `cat`:

``` shell
$ cd src/brainfuck
$ cat examples/foo_input.txt
foo
$ cat examples/cat.bf
,[.,]
$ ./translator.py examples/cat.bf target.out
source LoC: 1 code instr: 6
$ cat target.out
[{"index": 0, "opcode": "input", "term": [1, 1, ","]},
 {"index": 4, "opcode": "jz", "arg": 5, "term": [1, 2, "["]},
 {"index": 2, "opcode": "print", "term": [1, 3, "."]},
 {"index": 3, "opcode": "input", "term": [1, 4, ","]},
 {"index": 4, "opcode": "jmp", "arg": 1, "term": [1, 5, "]"]},
 {"opcode": "halt"}]⏎
$ ./machine.py target.out examples/foo_input.txt
DEBUG:root:TICK:   0 PC:   0 ADDR:   0 MEM_OUT: 0 ACC: 0  input  (','@1:1)
DEBUG:root:input: 'f'
DEBUG:root:TICK:   2 PC:   1 ADDR:   0 MEM_OUT: 102 ACC: 0  jz 5  ('['@1:2)
DEBUG:root:TICK:   4 PC:   2 ADDR:   0 MEM_OUT: 102 ACC: 102  print  ('.'@1:3)
DEBUG:root:output: '' << 'f'
DEBUG:root:TICK:   6 PC:   3 ADDR:   0 MEM_OUT: 102 ACC: 102  input  (','@1:4)
DEBUG:root:input: 'o'
DEBUG:root:TICK:   8 PC:   4 ADDR:   0 MEM_OUT: 111 ACC: 102  jmp 1  (']'@1:5)
DEBUG:root:TICK:   9 PC:   1 ADDR:   0 MEM_OUT: 111 ACC: 102  jz 5  ('['@1:2)
DEBUG:root:TICK:  11 PC:   2 ADDR:   0 MEM_OUT: 111 ACC: 111  print  ('.'@1:3)
DEBUG:root:output: 'f' << 'o'
DEBUG:root:TICK:  13 PC:   3 ADDR:   0 MEM_OUT: 111 ACC: 111  input  (','@1:4)
DEBUG:root:input: 'o'
DEBUG:root:TICK:  15 PC:   4 ADDR:   0 MEM_OUT: 111 ACC: 111  jmp 1  (']'@1:5)
DEBUG:root:TICK:  16 PC:   1 ADDR:   0 MEM_OUT: 111 ACC: 111  jz 5  ('['@1:2)
DEBUG:root:TICK:  18 PC:   2 ADDR:   0 MEM_OUT: 111 ACC: 111  print  ('.'@1:3)
DEBUG:root:output: 'fo' << 'o'
DEBUG:root:TICK:  20 PC:   3 ADDR:   0 MEM_OUT: 111 ACC: 111  input  (','@1:4)
DEBUG:root:input: '\n'
DEBUG:root:TICK:  22 PC:   4 ADDR:   0 MEM_OUT: 10 ACC: 111  jmp 1  (']'@1:5)
DEBUG:root:TICK:  23 PC:   1 ADDR:   0 MEM_OUT: 10 ACC: 111  jz 5  ('['@1:2)
DEBUG:root:TICK:  25 PC:   2 ADDR:   0 MEM_OUT: 10 ACC: 10  print  ('.'@1:3)
DEBUG:root:output: 'foo' << '\n'
DEBUG:root:TICK:  27 PC:   3 ADDR:   0 MEM_OUT: 10 ACC: 10  input  (','@1:4)
WARNING:root:Input buffer is empty!
INFO:root:output_buffer: 'foo\n'
```

Пример проверки исходного кода:

``` shell
$ poetry run pytest . -v --update-goldens
=================================== test session starts ====================================
platform darwin -- Python 3.12.0, pytest-7.4.3, pluggy-1.3.0 -- /Users/ryukzak/Library/Caches/pypoetry/virtualenvs/brainfuck-NIOcuFng-py3.12/bin/python
cachedir: .pytest_cache
rootdir: /Users/ryukzak/edu/csa/src/brainfuck
configfile: pyproject.toml
plugins: golden-0.2.2
collected 6 items                                                                          

integration_test.py::test_translator_and_machine[golden/cat.yml] PASSED              [ 16%]
integration_test.py::test_translator_and_machine[golden/hello.yml] PASSED            [ 33%]
integration_test.py::TestTranslatorAndMachine::test_cat_example PASSED               [ 50%]
integration_test.py::TestTranslatorAndMachine::test_cat_example_log PASSED           [ 66%]
integration_test.py::TestTranslatorAndMachine::test_hello_example PASSED             [ 83%]
machine.py::machine.DataPath.signal_wr PASSED                                        [100%]

==================================== 6 passed in 0.14s =====================================
$ poetry run ruff check .
$ poetry run ruff format .
4 files left unchanged
```

```text
| ФИО                            | алг   | LoC | code байт | code инстр. | инстр. | такт. | вариант |
| Пенской Александр Владимирович | hello | ... | -         | ...         | ...    | ...   | ...     |
| Пенской Александр Владимирович | cat   | 1   | -         | 6           | 15     | 28    | ...     |
```

import os
def rva_to_physical(rva):
    i = 0
    while i < Number_of_Sections - 1:
        if rva in range(section_rva_list[i], section_rva_list[i + 1]):
            break
        i += 1
    if i < Number_of_Sections:
        return rva - section_rva_list[i] + pointer_raw_data[i]
    else:
        return rva - section_rva_list[i-1] + pointer_raw_data[i]


def mz_header():
    global pfile
    print("MZ header")
    print("---------")
    for i in MZHeader_descriptors:
        if i == "Offset to New EXE Header":
            data = int.from_bytes(file.read(4), 'little')
            print("{0}     {1}     {2}".format(format(pfile, '08x'), format(data, '08x'), i))
            pfile += 4
            return data
        else:
            data = int.from_bytes(file.read(2), 'little')
            print("{0}     {1}         {2}".format(format(pfile, '08x'), format(data, '04x'), i))
            pfile += 2


def pe_header():
    global pfile, Number_of_Sections
    print("PE header")
    print("---------")

    for i in PEHeader_descriptors:
        if i in ["Magic --> PE", "Time Date Stamp", "Pointer to Symbol Table", "Number of Symbols"]:
            data = int.from_bytes(file.read(4), 'little')
            print("{0}     {1}     {2}".format(format(pfile, '08x'), format(data, '08x'), i))
            pfile += 4
        else:
            data = int.from_bytes(file.read(2), 'little')
            print("{0}     {1}         {2}".format(format(pfile, '08x'), format(data, '04x'), i[0:len(i)]))
            pfile += 2
            if i == "Number of Sections":
                Number_of_Sections = data


def converting_tables_creator():
    pointer = pfile
    section_rva = pointer + 220

    for i in range(Number_of_Sections):
        file.seek(section_rva)
        data = int.from_bytes(file.read(4), 'little')
        section_rva_list.append(data)
        section_rva += 8
        file.seek(section_rva)
        data = int.from_bytes(file.read(4), 'little')
        pointer_raw_data.append(data)
        section_rva += 32
    file.seek(pointer)


def optional_header():
    global pfile, export_rva, import_rva
    print("Optional header")
    print("---------------")
    for i in OptionalHeader_descriptors:
        if i in ["Major Linker Version", "Minor Linker Version"]:
            data = int.from_bytes(file.read(1), 'little')
            print("{0}     {1}           {2}".format(format(pfile, '08x'), format(data, '02x'), i))
            pfile += 1
        elif i in ["Magic", "Major O/S Version", "Minor O/S Version", "Major Image Version",
                   "Minor Image Version", "Major Subsystem Version", "Minor Subsystem Version",
                   "Subsystem", "DLL Characteristics"]:
            data = int.from_bytes(file.read(2), 'little')
            print("{0}     {1}         {2}".format(format(pfile, '08x'), format(data, '04x'), i[0:len(i)]))
            pfile += 2
        else:
            if i == "Address of Entry Point":
                converting_tables_creator()
                data = int.from_bytes(file.read(4), 'little')
                print("{0}     {1}     {2}     (physical: {3})".format(format(pfile, '08x'), format(data, '08x'), i,
                                                                       format(rva_to_physical(data), '08x')))
                pfile += 4
            else:
                data = int.from_bytes(file.read(4), 'little')
                print("{0}     {1}     {2}".format(format(pfile, '08x'), format(data, '08x'), i))
                pfile += 4
    for i in DataDirectories_descriptors:
        print("---------------------------------------------")
        data = int.from_bytes(file.read(4), 'little')
        print("{0}     {1}     {2}      {3}".format(format(pfile, '08x'), format(data, '08x'), "RVA", i))
        pfile += 4
        if i == "EXPORT Table":
            export_rva = data
        if i == "IMPORT Table":
            import_rva = data

        data = int.from_bytes(file.read(4), 'little')
        print("{0}     {1}     {2}".format(format(pfile, '08x'), format(data, '08x'), "Size"))
        pfile += 4


def section_headers():
    global pfile, section_rva_list, pointer_raw_data
    print("Section headers")
    print("---------------")
    for i in range(Number_of_Sections):
        for j in SectionHeader_descriptors:
            if j == "Name":
                data = file.read(8).decode("UTF-8")
                print("{0}     {1}        {2}".format(format(pfile, '08x'), data, j))
                pfile += 8
            elif j in ["Number of Relocations", "Number of Line Numbers"]:
                data = int.from_bytes(file.read(2), 'little')
                print("{0}     {1}         {2}".format(format(pfile, '08x'), format(data, '04x'), j))
                pfile += 2
            else:
                data = int.from_bytes(file.read(4), 'little')
                print("{0}     {1}     {2}".format(format(pfile, '08x'), format(data, '08x'), j))
                pfile += 4
        print("---------------------------------------------")


def import_table():
    print("Import table")
    print("------------")
    pointer = rva_to_physical(import_rva)
    while True:

        data = int.from_bytes(table_string[pointer:pointer+4], "little")

        if data == 0:
            break
        else:
            print("\tImport directory\n\t----------------")
            print("\t\t{0}     {1}         {2}".format(format(pointer, '08x'), format(data, '08x'),
                                                       "Import Name Table RVA"))
            pointer += 4
        for i in ImportDirectory_descriptors:
            data = int.from_bytes(table_string[pointer:pointer+4], "little")
            pointer += 4
            print("\t\t{0}     {1}         {2}".format(format(pointer, '08x'), format(data, '08x'), i), end='')
            if i == "Name RVA":
                name_pointer = rva_to_physical(data)
                name = b''
                while not table_string[name_pointer:name_pointer+1] == b'\x00':
                    name += table_string[name_pointer:name_pointer+1]
                    name_pointer += 1
                print(" --> {}".format(name.decode("UTF-8")))
            else:
                print()
        print("\t\tImport Thunks\n\t\t-------------")
        thunk_pointer = rva_to_physical(data)
        while True:
            data = int.from_bytes(table_string[thunk_pointer:thunk_pointer+4], "little")
            name = b''
            if data == 0:
                break

            name_pointer = rva_to_physical(data)
            hint = int.from_bytes(table_string[name_pointer:name_pointer+2], "little")
            name_pointer += 2
            if data >= int.from_bytes(b'\x80\x00\x00\x00', "big"):
                print("\t\t\tApi: {0} (phys: {1}) --> Hint: {2}, Name: {3}".format(format(name_pointer, '08x'),
                                                                                   format(data, '08x'),
                                                                                   format(hint, '04x'),
                                                                                   name.decode("UTF-8")))
                thunk_pointer += 4
                continue
            while not table_string[name_pointer:name_pointer+1] == b'\x00':
                name += table_string[name_pointer:name_pointer + 1]
                name_pointer += 1
            print("\t\t\tApi: {0} (phys: {1}) --> Hint: {2}, Name: {3}".format(format(name_pointer, '08x'),
                                                                               format(data, '08x'),
                                                                               format(hint, '04x'),
                                                                               name.decode("UTF-8")))
            thunk_pointer += 4

        print()


def export_table():
    if export_rva == 0:
        return
    number_of_functions = 0

    print("Export table")
    print("------------")
    print("\tExport directory\n\t--------------")
    pointer = rva_to_physical(export_rva)
    for i in ExportDirectory_descriptors:
        if i in ["Major Version", "Minor Version"]:
            data = int.from_bytes(table_string[pointer:pointer+2], "little")
            print("\t{0}     {1}             {2}".format(format(pointer, '08x'), format(data, '04x'), i))
            pointer += 2
        else:
            data = int.from_bytes(table_string[pointer:pointer + 4], "little")
            pointer += 4
            print("\t{0}     {1}         {2}".format(format(pointer, '08x'), format(data, '08x'), i), end='')
            if i == "Name RVA":
                name_pointer = rva_to_physical(data)
                name = b''
                while not table_string[name_pointer:name_pointer + 1] == b'\x00':
                    name += table_string[name_pointer:name_pointer + 1]
                    name_pointer += 1
                print(" --> {}".format(name.decode("UTF-8")))
            else:
                print()
            if i == "Number of Functions":
                number_of_functions = data
            if i == "Number of Names":
                number_of_names = data
            if i == "Address Table RVA":
                address_table_rva = data
            if i == "Name Pointer Table RVA":
                name_table_rva = data
            if i == "Ordinal Table RVA":
                ordinal_table_rva = data
            if i == "Ordinal Base":
                ordinal_base = data
    print()
    ordinal_name_dictionary = {}
    ordinal_list = []

    name_pointer_table = rva_to_physical(name_table_rva)
    name_pointer_table_save = name_pointer_table

    ordinal_pointer = rva_to_physical(ordinal_table_rva)

    for i in range(number_of_names):
        data = int.from_bytes(table_string[name_pointer_table:name_pointer_table+4], "little")
        name_pointer = rva_to_physical(data)
        name = b''

        while not table_string[name_pointer:name_pointer + 1] == b'\x00':
            name += table_string[name_pointer:name_pointer + 1]
            name_pointer += 1

        name_pointer += 1
        name = name.decode("UTF-8")
        ordinal = int.from_bytes(table_string[ordinal_pointer:ordinal_pointer+2], "little")
        ordinal_name_dictionary[ordinal] = [name, data]
        ordinal_list.append(ordinal)
        ordinal_pointer += 2
        name_pointer_table += 4
    address_pointer = rva_to_physical(address_table_rva)
    print("\tExport address table\n\t--------------------")
    start_ordinal = min(ordinal_list)
    for i in range(number_of_names):
        data = int.from_bytes(table_string[address_pointer:address_pointer+4], "little")
        print("\t\tApi: {0} (phys: {1}) --> Ordinal: {2}, Name: {3}".format(format(address_pointer, '08x'),
                                                                            format(data, '08x'),
                                                                            format(i, '04x'),
                                                                            ordinal_name_dictionary[i
                                                                                                    + start_ordinal][0]))
        address_pointer += 4
    print("\n\tExport function name table\n\t--------------------------")
    for i in range(number_of_names):
        data = int.from_bytes(table_string[name_pointer_table_save:name_pointer_table_save + 4], "little")
        ordinal = ordinal_list[i]
        print("\t\tApi: {0} (phys: {1}) --> Ordinal: {2}, Name: {3}".format(format(name_pointer_table_save, '08x'),
                                                                            format(data, '08x'),
                                                                            format(ordinal, '04x'),
                                                                            ordinal_name_dictionary[ordinal][0]))
        name_pointer_table_save += 4
    print("\n\tExport ordinal table\n\t--------------------------")
    for value in ordinal_list:
        print("\t\tValue: {0} (decoded ordinal: {1}), Name: {2}".format(format(value, '04x'),
                                                                        format(value + ordinal_base, '04x'),
                                                                        ordinal_name_dictionary[value][0]))


def os_check():
    file.seek(60)
    data = int.from_bytes(file.read(4), 'little')
    file.seek(data + 24)
    data = int.from_bytes(file.read(2), 'little')
    file.seek(0)
    if hex(data) == "0x10b":
        return True
    else:
        return False


def parse():
    global pfile, table_string
    pe_pointer = mz_header()
    file.read(pe_pointer - pfile)
    pfile = pe_pointer
    pe_header()
    optional_header()
    section_headers()
    table_string = file.read()
    table_string = b'\x00' * pfile + table_string
    import_table()
    export_table()


def main():
    if os_check():
        parse()
    else:
        print("Application not supported (32-bit required)")


filename = input("Input the file path: ")
try:
    file = open(filename, mode="rb")
except FileNotFoundError:
    print("File not found")
    exit(0)
pfile = 0
Number_of_Sections = 0
export_rva = 0
table_string = b''
import_rva = 0

section_rva_list = []
pointer_raw_data = []
MZHeader_descriptors = ["Magic --> MZ", "Bytes on Last Page of File", "Pages in File", "Relocations",
                        "Size of HEader in Paragraphs", "Minimum Extra Paragraphs",
                        "Maximum Extra Paragraphs", "Initial Relative SS", "Initial SP",
                        "Checksum", "Initial IP", "Initial Relative CS", "Offset To Relocation Table",
                        "Overlay Number", "Reserved", "Reserved", "Reserved", "Reserved", "OEM Identifier",
                        "OEM Information", "Reserved", "Reserved", "Reserved", "Reserved", "Reserved",
                        "Reserved", "Reserved", "Reserved", "Reserved", "Reserved", "Offset to New EXE Header"]
PEHeader_descriptors = ["Magic --> PE", "Machine", "Number of Sections", "Time Date Stamp",
                        "Pointer to Symbol Table", "Number of Symbols", "Size of Optional Header", "Characteristics"]
OptionalHeader_descriptors = ["Magic", "Major Linker Version", "Minor Linker Version", "Size of Code",
                              "Size of Initialized Data", "Size of Uninitialized Data", "Address of Entry Point",
                              "Base of Code", "Base of Data", "Image Base", "Section Alignment", "File Alignment",
                              "Major O/S Version", "Minor O/S Version", "Major Image Version", "Minor Image Version",
                              "Major Subsystem Version", "Minor Subsystem Version", "Win32 Version Value",
                              "Size of Image", "Size Of Headers", "Checksum", "Subsystem", "DLL Characteristics",
                              "Size of Stack Reverse", "Size of Stack Commit", "Size of Heap Reverse",
                              "Size of Heap Commit", "Loader Flags", "Number of Data Directories"]
DataDirectories_descriptors = ["EXPORT Table", "IMPORT Table", "RESOURCE Table", "EXCEPTION Table", "CERTIFICATE Table",
                               "BASE RELOCATION Table", "DEBUG Directory", "Architecture Specific Data",
                               "GLOBAL POINTER Register", "TLS Table", "LOAD CONFIGURATION Table", "BOUND IMPORT Table",
                               "IMPORT Address Table", "DELAY IMPORT Descriptors", "CLI Header", ""]

SectionHeader_descriptors = ["Name", "Virtual Size", "RVA", "Size of Raw Data", "Pointer to Raw Data",
                             "Pointer to Relocations", "Pointer to Line Numbers", "Number of Relocations",
                             "Number of Line Numbers", "Characteristics"]
ImportDirectory_descriptors = ["Time Date Stamp", "Forwarder Chain", "Name RVA",
                               "Import Address Table RVA"]
ExportDirectory_descriptors = ["Characteristics", "Time Date Stamp", "Major Version", "Minor Version", "Name RVA",
                               "Ordinal Base", "Number of Functions", "Number of Names", "Address Table RVA",
                               "Name Pointer Table RVA", "Ordinal Table RVA"]

main()
file.close()
os.system("PAUSE")

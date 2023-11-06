import argparse
import os
from contextlib import nullcontext
from pathlib import Path
from subprocess import Popen, PIPE


BANNER_SIGN = "="
BANNER_SIGN_COUNT = 20
BANNER_COLOR = "\033[92m"  # Green


def print_banner(text):
    print(
        f"\n{BANNER_COLOR}"
        + BANNER_SIGN * BANNER_SIGN_COUNT
        + f" {text} "
        + BANNER_SIGN * BANNER_SIGN_COUNT
        + "\n\033[0m"
    )


def build_file_path(output_directory, filename):
    return None if output_directory is None else Path(output_directory) / filename


def process_output(process, path=None):
    with open(path, "w+") if path is not None else nullcontext() as file:
        while process.poll() is None:
            line = process.stdout.readline().decode()

            print(line, end="")
            if file:
                file.write(line)

        remaining_text = process.stdout.read().decode()

        print(remaining_text, end="")
        if file:
            file.write(remaining_text)


def nmap_stage(host):
    process = Popen(["nmap", "-T4", "-p-", host], stdout=PIPE, stderr=PIPE)

    ports = []

    while process.poll() is None:
        line = process.stdout.readline()

        print(line.decode(), end="")

        if "/tcp" in line.decode():
            ports.append(line.decode().split("/")[0])

    print(process.stdout.read().decode(), end="")

    return ports


def nmap_full(host, ports, output_directory):
    process_args = [
        "nmap",
        "-T4",
        "-p",
        ",".join(ports),
        "-A",
        "--script=version,vuln",
        host,
    ]

    if output_directory:
        process_args.extend(["-oA", build_file_path(output_directory, "nmap")])

    process = Popen(
        process_args,
        stdout=PIPE,
        stderr=PIPE,
    )

    process_output(process)


def nikto(host, output_directory):
    process = Popen(["nikto", "-h", host], stdout=PIPE, stderr=PIPE)

    process_output(process, build_file_path(output_directory, "nikto.txt"))


def whatweb(host, output_directory):
    process = Popen(["whatweb", "-v", host], stdout=PIPE, stderr=PIPE)

    process_output(process, build_file_path(output_directory, "whatweb.txt"))


def gobuster(host, output_directory, dirlist):
    process = Popen(
        ["gobuster", "dir", "-u", host, "-w", dirlist], stdout=PIPE, stderr=PIPE
    )

    process_output(process, build_file_path(output_directory, "gobuster.txt"))


def main(host, output_directory, dirlist):
    print_banner("NMAP STAGED")
    ports = nmap_stage(host)

    print_banner("NMAP FULL")
    nmap_full(host, ports, output_directory)

    if "80" in ports:
        print_banner("NIKTO SCAN")
        nikto(host, output_directory)

        print_banner("WHATWEB")
        whatweb(host, output_directory)

        if dirlist:
            print_banner("GOBUSTER DIRECTORY WORDLIST")
            gobuster(host, output_directory, dirlist)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan and enumerate a target.")

    parser.add_argument(
        "-H", "--host", type=str, required=True, help="the host to scan and enumerate"
    )
    parser.add_argument(
        "-o",
        "--out",
        type=str,
        required=False,
        help="save scans and enumerations in the specified directory",
        dest="dir",
    )
    parser.add_argument(
        "-d",
        "--dirlist",
        type=str,
        required=False,
        help="brute force directories with specified wordlist if webserver is present",
        dest="dirlist",
    )

    parser.formatter_class = lambda prog: argparse.RawTextHelpFormatter(
        prog, max_help_position=40
    )

    args = parser.parse_args()

    if args.dir and not os.path.isdir(args.dir):
        raise SystemExit(f"Error: directory '{args.dir}' does not exist.")

    if args.dirlist and not os.path.isfile(args.dirlist):
        raise SystemExit(f"Error: file '{args.dirlist}' does not exist.")

    main(args.host, args.dir, args.dirlist)

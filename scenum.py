import argparse
import os
from subprocess import Popen, PIPE

BANNER_SIGN = "="
BANNER_SIGN_COUNT = 20


def print_banner(text):
    print(
        "\n"
        + BANNER_SIGN * BANNER_SIGN_COUNT
        + f" {text} "
        + BANNER_SIGN * BANNER_SIGN_COUNT
        + "\n"
    )


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
    process = Popen(
        ["nmap", "-T4", "-p", ",".join(ports), "-A", "--script=version,vuln", host],
        stdout=PIPE,
        stderr=PIPE,
    )

    while process.poll() is None:
        line = process.stdout.readline()

        print(line.decode(), end="")

    print(process.stdout.read().decode(), end="")


def main(host, output_directory):
    print_banner("NMAP STAGED")
    ports = nmap_stage(host)

    print_banner("NMAP FULL")
    nmap_full(host, ports, output_directory)


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
        help="the directory to put scans and enumerate results in, current directory by default",
        dest="dir",
    )

    args = parser.parse_args()

    if args.dir == None:
        args.dir = os.getcwd()

    if not os.path.isdir(args.dir):
        raise SystemExit(f"Error: directory '{args.dir}' does not exist.")

    main(args.host, args.dir)

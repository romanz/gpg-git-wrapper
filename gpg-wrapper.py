#!/usr/bin/env python3
import binascii
import contextlib
import pathlib
import subprocess
import sys
import tempfile

here = pathlib.Path(__file__).parent
log = here / "log.txt"
logfile = log.open("at")

PGP_PREFIX = "-----BEGIN PGP SIGNATURE-----\n"
UNTRUSTED_COMMENT = "untrusted comment: "


def line_to_skip(line):
    return any(line.startswith(prefix) for prefix in PREFIXES_TO_SKIP)


def parse_keyid(encoded):
    data = binascii.a2b_base64(encoded)
    return data[:10]


def iter_pubkeys(keyid):
    pubkeys = here / ".pubkeys"
    for line in pubkeys.open():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        pubkey, label = line.split(" ", 1)
        if keyid == parse_keyid(pubkey):
            yield pubkey, label


@contextlib.contextmanager
def temp_file(contents):
    with tempfile.NamedTemporaryFile("wt") as f:
        f.write(contents)
        f.flush()
        yield f


def verify(pubkey, sig):
    with temp_file(pubkey) as pubkey_file, temp_file(sig) as sig_file:
        try:
            output = subprocess.check_output(["signify-openbsd", "-V", "-m-", f"-x{sig_file.name}", f"-p{pubkey_file.name}"])
            return output == b"Signature Verified\n"
        except subprocess.CalledProcessError:
            return False


def main():
    args = sys.argv[1:]
    if not args:
        return

    if args[1] == "-bsau":  # b=detached s=sign a=armored u=user
        assert args[0] == "--status-fd=2", args
        user_id = args[2]
        output = subprocess.check_output(["trezor-signify", "sign", user_id]).decode()
        sys.stdout.write(PGP_PREFIX + output)
        sys.stderr.write("\n[GNUPG:] SIG_CREATED ")

    if args[2] == "--verify":
        assert args[1] == "--status-fd=1"
        assert args[4] == "-"
        sig_lines = list(open(args[3]))
        assert sig_lines[0] == PGP_PREFIX
        if sig_lines[1].startswith(UNTRUSTED_COMMENT):
            sig_comment, sig_value = sig_lines[1:]
            sig = f'{sig_comment}{sig_value}'

            keyid = parse_keyid(sig_value)
            for pubkey, label in iter_pubkeys(keyid):
                if verify(pubkey=f'{UNTRUSTED_COMMENT}{label}\n{pubkey}\n', sig=sig):
                    sys.stderr.write(f'Good signature from {pubkey} "{label}"\n')
                    sys.stdout.write("\n[GNUPG:] GOODSIG ")
                else:
                    sys.stderr.write(f'Bad signature from {pubkey} "{label}"\n')
                    sys.stdout.write("\n[GNUPG:] BADSIG ")
                return

            sys.stdout.write("\n[GNUPG:] ERRSIG ")
            sys.stderr.write(f'Can\'t check signature: No public key {keyid.hex()}\n')


if __name__ == '__main__':
    try:
        main()
    except:
        import traceback
        traceback.print_exc(file=logfile)

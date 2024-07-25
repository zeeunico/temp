from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from colorama import init, Fore, Style
import os

# Initialize colorama
init()

def encrypt_text(key, plaintext):
    backend = default_backend()
    
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)
    
    # Ensure the key is 32 bytes (AES-256)
    key = key.ljust(32, b'\0')
    
    # Pad the plaintext to be a multiple of 16 bytes (AES block size)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    
    # Create a cipher object using AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    
    # Encrypt the plaintext
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return the IV and ciphertext as bytes
    return iv + ciphertext


def decrypt_text(key, encrypted_data):
    backend = default_backend()
    
    # Extract the IV from the encrypted data
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    # Ensure the key is 32 bytes (AES-256)
    key = key.ljust(32, b'\0')
    
    # Create a cipher object using AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad the plaintext
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    
    # Return the decrypted plaintext as a string
    return plaintext.decode()

def display_options():
    print(Fore.YELLOW + Style.BRIGHT + "It'S OuR OwN PlaygrounD. Let'S PlaY!" + Style.RESET_ALL)
    print(Fore.YELLOW + Style.BRIGHT + "====================================" + Style.RESET_ALL)
    print()
    
    choice = input(Fore.CYAN + Style.BRIGHT+ "[1] Kill\n[2] Die\n[Q] Quit\n\nEnter Your Choice: " + Style.RESET_ALL).strip()
    
    if choice.lower() == 'q':
        return
    
    elif choice == '1':
        print()
        plaintext = input(Fore.YELLOW + Style.BRIGHT+ "Whom to Kill? => " + Style.RESET_ALL)
        key = input(Fore.YELLOW + Style.BRIGHT+ "WHY? => " + Style.RESET_ALL).encode('utf-8')
        
        encrypted_data = encrypt_text(key, plaintext)
        
        print(Fore.GREEN + Style.BRIGHT+ "\nMission Successful!" + Style.RESET_ALL)
        print(Fore.GREEN + Style.BRIGHT+ "Mission Serial No: " + Style.RESET_ALL + Fore.WHITE + encrypted_data.hex() + Style.RESET_ALL)
    
    elif choice == '2':
        
        try:
            key = input(Fore.YELLOW + Style.BRIGHT+ "WHY? => " + Style.RESET_ALL).encode('utf-8')
            encrypted_data = input(Fore.YELLOW + Style.BRIGHT+ "Last Wish => " + Style.RESET_ALL).strip()
            encrypted_data = bytes.fromhex(encrypted_data)
            decrypted_text = decrypt_text(key, encrypted_data)
            
            print(Fore.GREEN + Style.BRIGHT+ "\nYou're Dead Now!" + Style.RESET_ALL)
            print(Fore.GREEN + Style.BRIGHT+ "Death Note: " + Style.RESET_ALL + Fore.WHITE + decrypted_text + Style.RESET_ALL)
        except:
            print(Fore.RED + Style.BRIGHT + "\n'''''''''''YoU CaN NeveR CatcH ME!'''''''''''" + Style.RESET_ALL)
    
    else:
        print(Fore.RED + Style.BRIGHT+ "\nInvalid Choice! Please Enter a Valid Option." + Style.RESET_ALL)
    
    print()
    input(Fore.CYAN + Style.BRIGHT+ "Press Enter to Continue..." + Style.RESET_ALL)
    print()
    display_options()

def display_gui():
    print(Fore.GREEN + Style.BRIGHT + """
                                         .----------------. 
                                        | .--------------. |
                                        | |    ______    | |
                                        | |   / _ __ `.  | |
                                        | |  |_/____) |  | |
                                        | |    /  ___.'  | |
                                        | |    |_|       | |
                                        | |    (_)       | |
                                        | |              | |
                                        | '--------------' |
                                         '----------------' 
                                         .----------------. 
                                        | .--------------. |
                                        | |    ______    | |
                                        | |   / _ __ `.  | |
                                        | |  |_/____) |  | |
                                        | |    /  ___.'  | |
                                        | |    |_|       | |
                                        | |    (_)       | |
                                        | |              | |
                                        | '--------------' |
                                         '----------------' 
 .----------------.  .----------------.  .----------------.  .----------------.  .----------------. 
| .--------------. || .--------------. || .--------------. || .--------------. || .--------------. |
| |    ______    | || | _____  _____ | || |  ____  ____  | || |  ____  ____  | || |    ______    | |
| |   / _ __ `.  | || ||_   _||_   _|| || | |_   ||   _| | || | |_  _||_  _| | || |   / _ __ `.  | |
| |  |_/____) |  | || |  | | /\ | |  | || |   | |__| |   | || |   \ \  / /   | || |  |_/____) |  | |
| |    /  ___.'  | || |  | |/  \| |  | || |   |  __  |   | || |    \ \/ /    | || |    /  ___.'  | |
| |    |_|       | || |  |   /\   |  | || |  _| |  | |_  | || |    _|  |_    | || |    |_|       | |
| |    (_)       | || |  |__/  \__|  | || | |____||____| | || |   |______|   | || |    (_)       | |
| |              | || |              | || |              | || |              | || |              | |
| '--------------' || '--------------' || '--------------' || '--------------' || '--------------' |
 '----------------'  '----------------'  '----------------'  '----------------'  '----------------' 
    """ + Style.RESET_ALL)
    
    display_options()
    
    

# Main function to start the program
if __name__ == "__main__":
    display_gui()
import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
import base64

def generate_key_and_iv(password, salt):
    """
    Generate a 256-bit key and a 128-bit IV using the provided password and salt.
    """
    key = scrypt(password, salt, 32, N=2**14, r=8, p=1)  # Derive key from password using scrypt
    iv = get_random_bytes(16)  # Generate a random 16-byte IV
    return key, iv

def encrypt_text(text, password):
    """
    Encrypt the provided text using AES (CBC mode) with the provided password.
    """
    salt = get_random_bytes(16)  # Generate a random 16-byte salt
    key, iv = generate_key_and_iv(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create AES cipher with the generated key and IV
    padded_text = pad(text.encode(), AES.block_size)  # Pad the text to a multiple of AES block size
    ciphertext = cipher.encrypt(padded_text)  # Encrypt the padded text
    return base64.b64encode(salt + iv + ciphertext).decode()  # Encode the salt, IV, and ciphertext in base64

def decrypt_text(ciphertext, password):
    """
    Decrypt the provided ciphertext using AES (CBC mode) with the provided password.
    """
    ciphertext = base64.b64decode(ciphertext)  # Decode the base64 encoded ciphertext
    salt = ciphertext[:16]  # Extract the salt from the ciphertext
    iv = ciphertext[16:32]  # Extract the IV from the ciphertext
    ciphertext = ciphertext[32:]  # Extract the actual ciphertext
    key, _ = generate_key_and_iv(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create AES cipher with the derived key and extracted IV
    decrypted_text = cipher.decrypt(ciphertext)  # Decrypt the ciphertext
    unpadded_text = unpad(decrypted_text, AES.block_size)  # Remove the padding from the decrypted text
    return unpadded_text.decode()

def process_text():
    """
    Process the input text based on the selected operation (encrypt/decrypt) and display the result.
    """
    input_text = input_entry.get("1.0", "end-1c")  # Get the input text from the Text widget
    password = password_entry.get()  # Get the password from the Entry widget
    if encrypt_decrypt_var.get() == "Encrypt":
        encrypted_text = encrypt_text(input_text, password)
        output_entry.delete("1.0", "end")  # Clear the output Text widget
        output_entry.insert("1.0", encrypted_text)  # Insert the encrypted text into the output Text widget
    elif encrypt_decrypt_var.get() == "Decrypt":
        try:
            decrypted_text = decrypt_text(input_text, password)
            output_entry.delete("1.0", "end")  # Clear the output Text widget
            output_entry.insert("1.0", decrypted_text)  # Insert the decrypted text into the output Text widget
        except Exception as e:
            messagebox.showerror("Error", str(e))  # Show an error message if decryption fails

# Initialize the main application window
root = tk.Tk()
root.title("AES Encryption/Decryption")
root.resizable(False, False)

# Create and pack the password input frame
encrypt_decrypt_var = tk.StringVar(value="Encrypt")
password_frame = tk.Frame(root)
password_frame.pack(pady=5)

# Create and pack the password label and entry widgets
password_label = tk.Label(password_frame, text="  Key:      ")
password_label.pack(side="left", padx=5)
password_entry = tk.Entry(password_frame, show="*", width=93)
password_entry.pack(side="left", padx=5)

# Create and pack the input text frame
input_frame = tk.Frame(root)
input_frame.pack(pady=5)

# Create and pack the input label and text widget
input_label = tk.Label(input_frame, text="   Text:    ")
input_label.pack(side="left", padx=5)
input_entry = tk.Text(input_frame, height=10, width=70)
input_entry.pack(side="left", padx=5)

# Create and pack the encryption/decryption option frame
encrypt_decrypt_frame = tk.Frame(root)
encrypt_decrypt_frame.pack(pady=5)

# Create and pack the encryption and decryption radio buttons
encrypt_radio = tk.Radiobutton(encrypt_decrypt_frame, text="Encrypt", variable=encrypt_decrypt_var, value="Encrypt")
encrypt_radio.pack(side="left", padx=5)
decrypt_radio = tk.Radiobutton(encrypt_decrypt_frame, text="Decrypt", variable=encrypt_decrypt_var, value="Decrypt")
decrypt_radio.pack(side="left", padx=5)

# Create and pack the output text frame
output_frame = tk.Frame(root)
output_frame.pack(pady=5)

# Create and pack the output label and text widget
output_label = tk.Label(output_frame, text="Output: ")
output_label.pack(side="left", padx=5)
output_entry = tk.Text(output_frame, height=10, width=70)
output_entry.pack(side="left", padx=5)

# Create and pack the process button
process_button = tk.Button(root, text="Process", command=process_text)
process_button.pack(pady=5)

# Start the main event loop
root.mainloop()

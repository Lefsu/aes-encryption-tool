### README: AES Encryption/Decryption Tool

---

#### Overview

This is a simple AES (Advanced Encryption Standard) Encryption/Decryption GUI application built using Python's `tkinter` library. It allows users to securely encrypt and decrypt text using a password of their choice. The encryption is performed using the AES algorithm in CBC (Cipher Block Chaining) mode, with key derivation using the `scrypt` key derivation function.

---

#### Features

- **AES Encryption**: Encrypt any text using a password, with AES in CBC mode.
- **AES Decryption**: Decrypt previously encrypted text using the same password.
- **Password-Based Key Derivation**: Securely derive encryption keys from passwords using `scrypt`.
- **Graphical User Interface**: User-friendly interface to input text, choose between encryption or decryption, and view the output.

---

#### Prerequisites

- **Python 3.x**: Ensure that Python 3.x is installed on your system.
- **Required Libraries**: You need to install the following Python libraries:
  - `tkinter`: For creating the GUI. Usually included with Python.
  - `pycryptodome`: For cryptographic functions. Install it via pip:
    ```sh
    pip install pycryptodome
    ```

---

#### Installation

1. **Clone the Repository**:
   ```sh
   git clone https://github.com/yourusername/aes-encryption-tool.git
   cd aes-encryption-tool
   ```

2. **Install Dependencies**:
   If you haven't already installed the dependencies, run:
   ```sh
   pip install pycryptodome
   ```

---

#### Usage

1. **Run the Application**:
   Run the Python script to start the GUI:
   ```sh
   python3 aes_encryption_tool.py
   ```

2. **Encrypting Text**:
   - Enter the text you want to encrypt in the "Text" field.
   - Enter your password in the "Key" field.
   - Select the "Encrypt" option.
   - Click the "Process" button. The encrypted text will appear in the "Output" field.

3. **Decrypting Text**:
   - Enter the encrypted text in the "Text" field.
   - Enter the password used during encryption in the "Key" field.
   - Select the "Decrypt" option.
   - Click the "Process" button. The decrypted text will appear in the "Output" field.

---

#### File Structure

- `aes_encryption_tool.py`: The main Python script containing the implementation of the AES encryption/decryption tool.

---

#### Security Notes

- **Password Security**: Ensure that the password you choose is strong and kept secure. The strength of encryption depends on the password.
- **Key Management**: The password-based key derivation function (`scrypt`) is used to generate secure keys from the password and salt, ensuring robust encryption.

---

#### License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

---

#### Acknowledgments

- **PyCryptodome**: For providing the cryptographic primitives.
- **Tkinter**: For the GUI components.

---

#### Contact

For any questions or suggestions, feel free to contact me on discord at Lefsu.
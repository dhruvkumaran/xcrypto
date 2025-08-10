import sys
import os
import webbrowser
import re
import unicodedata
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QLabel, QPushButton,
    QComboBox, QListWidget, QFileDialog, QLineEdit, QMessageBox, QStackedWidget, QDialog, QRadioButton, QButtonGroup
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QPixmap, QIcon
from PySide6.QtWidgets import QFileDialog, QMessageBox, QProgressBar, QProgressDialog
from PySide6.QtWidgets import QFileDialog, QInputDialog, QMessageBox  
from PySide6.QtCore import Signal, QObject
import zipfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
from PIL import Image
import py7zr
import base64

# ... (previous functions remain unchanged)
#added splashScreen Class methods
class SplashScreen(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Splash Screen")
        self.setGeometry(100, 100, 800, 600)

        # Splash Screen Layout
        central_widget = QWidget()
        layout = QVBoxLayout(central_widget)

        # Get the path to the current directory where the script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))

        # Define the path to the logo image
        logo_path = os.path.join(script_dir, 'background2.jpg')  # Change to your logo filename

        # Load the logo
        logo_label = QLabel()
        pixmap = QPixmap(logo_path)
        if pixmap.isNull():
            print("Error: Logo image could not be loaded.")
        logo_label.setPixmap(pixmap)
        logo_label.setAlignment(Qt.AlignCenter)

        # Text Label
        text_label = QLabel("Hey there! Super excited to e-meet you\nWelcome")
        text_label.setAlignment(Qt.AlignCenter)
        text_label.setStyleSheet("font-size: 20px; font-weight: bold;")

        # Add widgets to layout
        layout.addWidget(logo_label)
        layout.addWidget(text_label)

        self.setCentralWidget(central_widget)
# Main Application Class

def encrypt_data(data, password):
    # Generate a random 128-bit key
    key = hashlib.sha256(password.encode()).digest()

    # Create a new AES cipher object
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the data to a multiple of 16 bytes
    padded_data = data + b'\0' * (16 - len(data) % 16)

    # Encrypt the padded data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted_data

def decrypt_data(encrypted_data, password):
    # Generate the same 128-bit key using the password
    key = hashlib.sha256(password.encode()).digest()

    # Create a new AES cipher object
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding (trailing null bytes)
    decrypted_data = decrypted_data.rstrip(b'\0')

    return decrypted_data

class PreferenceDialog(QDialog):
    themeChanged = Signal(str)  # Use Signal instead of pyqtSignal in PySide6

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Preferences")
        self.setFixedSize(400, 300)

        layout = QVBoxLayout(self)

        # Online Translator Button
        translator_label = QLabel("Open Online Translator:")
        translator_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        translator_button = QPushButton("Online Language Translator")
        translator_button.clicked.connect(self.open_online_translator)

        # Theme Selection
        theme_label = QLabel("Select Theme:")
        theme_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.theme_group = QButtonGroup(self)
        light_theme = QRadioButton("Light")
        dark_theme = QRadioButton("Dark")
        default_theme = QRadioButton("Device Default")
        light_theme.setChecked(True)

        self.theme_group.addButton(light_theme)
        self.theme_group.addButton(dark_theme)
        self.theme_group.addButton(default_theme)

        light_theme.toggled.connect(self.set_light_theme)
        dark_theme.toggled.connect(self.set_dark_theme)
        default_theme.toggled.connect(self.set_default_theme)

        # Add Widgets to Layout
        layout.addWidget(translator_label)
        layout.addWidget(translator_button)
        layout.addWidget(theme_label)
        layout.addWidget(light_theme)
        layout.addWidget(dark_theme)
        layout.addWidget(default_theme)

        # OK Button
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        layout.addWidget(ok_button)

    def open_online_translator(self):
        """Open the online translator app."""
        webbrowser.open("https://translator-app-of1u.onrender.com/")

    def set_light_theme(self):
        """Apply light theme."""
        self.setStyleSheet("background-color: white; color: black;")
        self.themeChanged.emit("light")  # Emit signal

    def set_dark_theme(self):
        """Apply dark theme."""
        self.setStyleSheet("background-color: #2d2d2d; color: white;")
        self.themeChanged.emit("dark")  # Emit signal

    def set_default_theme(self):
        """Apply device default theme."""
        self.setStyleSheet("")
        self.themeChanged.emit("default")  # Emit signal
# Main Application Class
class AdvancedEncryptorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("XCrypto - Advanced Tool")
        self.setGeometry(100, 100, 1200, 800)
        icon_path = os.path.join(os.path.dirname(__file__), 'logo1.png')
        self.setWindowIcon(QIcon(icon_path))  

        # Main Layout
        main_widget = QWidget()
        main_layout = QHBoxLayout(main_widget)
        self.setCentralWidget(main_widget)

        # Left Panel (File Navigation)
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)

    

        add_dir_button = QPushButton("ADD DIRECTORY")
        add_dir_button.clicked.connect(self.add_directory)

        self.file_list = QListWidget()

        preference_button = QPushButton("PREFERENCE")
        preference_button.clicked.connect(self.show_preference)

        support_button = QPushButton("SUPPORT")
        support_button.clicked.connect(self.open_support)

        about_button = QPushButton("ABOUT")
        about_button.clicked.connect(self.show_about)

    
        left_layout.addWidget(add_dir_button)
        left_layout.addWidget(self.file_list)
        left_layout.addWidget(preference_button)
        left_layout.addWidget(support_button)
        left_layout.addWidget(about_button)

        # Center Panel (Main Interaction Area)
        center_panel = QWidget()
        center_layout = QVBoxLayout(center_panel)

        # Search Bar
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search...")
        self.search_bar.textChanged.connect(self.search_files)

        # File Dropdown
        self.file_dropdown = QComboBox()

        # Password Entry
        self.password_entry = QLineEdit()
        self.password_entry.setPlaceholderText("Enter Password")

        # File Buttons
        file_buttons_layout = QHBoxLayout()
        file_save_button = QPushButton("SAVE")
        file_save_button.clicked.connect(self.save_file)

        file_saveas_button = QPushButton("SAVE AS")
        file_saveas_button.clicked.connect(self.save_as_file)

        file_buttons_layout.addWidget(file_save_button)
        file_buttons_layout.addWidget(file_saveas_button)

        # Section B (Dynamic Content Area)
        self.section_b = QStackedWidget()
        self.home_label = QLabel(
            "                                                                 welcome to Xcrypto!\n\n"
            "                                                       This application is under deveolopment.\n\n"
            "                                           If you encounter any problems please report it to or support page!")
        
        self.about_label = QLabel(
            "About XCrypto\n\n"
            "XCrypto is an advanced encryption and decryption tool designed to provide top-notch security with a seamless user experience.\n" 
            "Built with a focus on simplicity and power, XCrypto allows you to easily protect your sensitive files and data using robust encryption algorithms,\n"
            "such as AES and RSA, and secure them with customizable passwords.\n\n"
            "Whether you're a casual user looking to protect your private documents or a tech enthusiast who values security,\n"
            "XCrypto provides an intuitive graphical interface with powerful features. The tool supports file encryption, decryption, and even the ability to\n"
            "hide data within images using steganography, ensuring your information remains secure and confidential.\n"
        )

        self.section_b.addWidget(self.home_label)
    
        self.section_b.addWidget(self.about_label)

        # Add to Center Layout
        center_layout.addWidget(self.search_bar)
        center_layout.addWidget(self.file_dropdown)
        center_layout.addWidget(self.password_entry)
        center_layout.addLayout(file_buttons_layout)
        center_layout.addWidget(self.section_b)

        # Add Panels to Main Layout
        main_layout.addWidget(left_panel, 1)
        main_layout.addWidget(center_panel, 3)

        # Rightmost Panel
        rightmost_panel = QWidget()
        rightmost_layout = QVBoxLayout(rightmost_panel)

        encrypt_button = QPushButton("ENCRYPT")
        encrypt_button.clicked.connect(self.encrypt_file)
        decrypt_button = QPushButton("DECRYPT")
        decrypt_button.clicked.connect(self.decrypt_file)
        hide_in_image_button = QPushButton("HIDE IN IMAGE")
        hide_in_image_button.clicked.connect(self.steganography_encode)
        reveal_image_button = QPushButton("REVEAL IMAGE")
        reveal_image_button.clicked.connect(self.steganography_decode)
        file_verify_button = QPushButton("FILE VERIFY")
        file_verify_button.clicked.connect(self.file_verify)
        key_library_button = QPushButton("KEY LIBRARY")
        key_library_button.clicked.connect(self.key_library)
        sanitize_button = QPushButton("SANITIZE")
        sanitize_button.clicked.connect(self.sanitize_data)

        self.zip_button = QPushButton("ZIP")
        self.zip_button.clicked.connect(self.zip_file)
        self.unzip_button = QPushButton("UNZIP")
        self.unzip_button.clicked.connect(self.unzip_file)

        rightmost_layout.addWidget(encrypt_button)
        rightmost_layout.addWidget(decrypt_button)
        rightmost_layout.addWidget(hide_in_image_button)
        rightmost_layout.addWidget(reveal_image_button)
        rightmost_layout.addWidget(file_verify_button)
        rightmost_layout.addWidget(key_library_button)
        rightmost_layout.addWidget(sanitize_button)
        rightmost_layout.addWidget(self.zip_button)
        rightmost_layout.addWidget(self.unzip_button)

        main_layout.addWidget(rightmost_panel, 1)

    # Method to show the home section
    def show_home(self):
        self.section_b.setCurrentWidget(self.home_label)

    # Method to show the about section
    def show_about(self):
        self.section_b.setCurrentWidget(self.about_label)

    # Method to show the preference dialog
    def show_preference(self):
        preferences = PreferenceDialog()
        preferences.exec()

    # Method to open the support page
    def open_support(self):
        webbrowser.open('https://sdksoftwares.github.io/Encrypterdecryptertool/')  # Replace with your support page URL

    # Method to search files
    def search_files(self):
       search_text = self.search_bar.text().strip().lower()
       for row in range(self.file_list.count()):
        item = self.file_list.item(row)
        # Show the item if the search text is found in the item's text
        item.setHidden(search_text not in item.text().lower())
    # Method to add a directory
    def add_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            self.file_list.clear()
            self.file_dropdown.clear()
            self.current_directory = directory
            for file in os.listdir(directory):
                self.file_list.addItem(file)
                self.file_dropdown.addItem(file)

    # Method to encrypt a file
    def encrypt_file(self):
       password = self.password_entry.text()
       selected_file = self.file_dropdown.currentText()
       if password and selected_file:
          file_path = os.path.join(self.current_directory, selected_file)
          with open(file_path, "rb") as f:
            data = f.read()
            encrypted_data = encrypt_data(data, password)
            temp_file_path = file_path + ".enc"
          with open(temp_file_path, "wb") as f:
            f.write(encrypted_data)
            QMessageBox.information(self, "Success", "Temporary encrypted file saved.")
            save_path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted File", "", "All Files (*)")
          if save_path:
            with open(save_path, "wb") as f:
                with open(temp_file_path, "rb") as temp_f:
                    f.write(temp_f.read())
            os.remove(temp_file_path)
            QMessageBox.information(self, "Success", "Encrypted file saved successfully.")
          else:
            QMessageBox.warning(self, "Input Error", "Please select a location to save the encrypted file.")
       else:
        QMessageBox.warning(self, "Input Error", "Password and file selection are required for encryption.")

    # Method to decrypt a file
    def decrypt_file(self):
        password = self.password_entry.text()
        selected_file = self.file_dropdown.currentText()
        if password and selected_file.endswith(".enc"):
            file_path = os.path.join(self.current_directory, selected_file)
            with open(file_path, "rb") as f:
                encrypted_data = f.read()
            try:
                decrypted_data = decrypt_data(encrypted_data, password)
                with open(file_path[:-4], "wb") as f:
                    f.write(decrypted_data)
                QMessageBox.information(self, "Success", "File decrypted successfully.")
            except Exception as e:
                QMessageBox.warning(self, "Decryption Error", str(e))
        else:
            QMessageBox.warning(self, "Input Error", "Valid encrypted file selection and password are required for decryption.")

    # Method to hide data in an image
    def steganography_encode(self):
        # Step 1: Select image file
        image_path, _ = QFileDialog.getOpenFileName(self, "Select Image", "", "Image Files (*.png *.jpg *.jpeg *.bmp *.gif)")
        if not image_path:
            QMessageBox.warning(self, "Input Error", "No image selected.")
            return
        
        # Step 2: Ask user to input data to hide
        data, ok = QInputDialog.getText(self, "Data Input", "Enter text or data to hide in image:")
        if not ok or not data:
            QMessageBox.warning(self, "Input Error", "Please enter some data to hide.")
            return

        # Step 3: Get the output file location (ensure correct extension is applied)
        output_path, selected_filter = QFileDialog.getSaveFileName(self, "Save Encoded Image", "", "PNG Image (*.png);;JPEG Image (*.jpg *.jpeg);;Bitmap Image (*.bmp);;GIF Image (*.gif)")
        if not output_path:
            QMessageBox.warning(self, "Save Error", "No location selected to save the encoded image.")
            return

        # Ensure the correct extension is applied based on user choice
        if not any(output_path.lower().endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".bmp", ".gif"]):
            extension = self.get_extension_from_filter(selected_filter)
            if not output_path.lower().endswith(extension):
                output_path += extension  # Add the appropriate extension if missing

        # Step 4: Encode data into the image
        try:
            self.steganography_encode_method(image_path, data, output_path)
            QMessageBox.information(self, "Success", "Data hidden in image successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred while encoding the data: {str(e)}")

    def steganography_encode_method(self, image_path, data, output_path):
        """Encode text data into the image."""
        img = Image.open(image_path)
        width, height = img.size

        # Convert the text data into binary format
        binary_data = ''.join(format(ord(char), '08b') for char in data)
        data_length = len(binary_data)

        data_index = 0

        # A simple dummy example of encoding: we convert the text into a byte and hide it
        encoded_image = img.copy()  # Create a copy of the image
        pixels = encoded_image.load()

        # Encoding the byte data into the image (modifying the red channel as an example)
        for y in range(height):
            for x in range(width):
                if data_index < data_length:
                    r, g, b = pixels[x, y]
                    # Modify the LSB of the red channel to store the data
                    r = (r & 0xFE) | int(binary_data[data_index])  # Set LSB of red channel
                    pixels[x, y] = (r, g, b)
                    data_index += 1
                
        encoded_image.save(output_path)  # Save the encoded image

    def get_extension_from_filter(self, filter_string):
        """Return the appropriate file extension based on the filter string."""
        if "PNG" in filter_string:
            return ".png"
        elif "JPEG" in filter_string:
            return ".jpg"
        elif "BMP" in filter_string:
            return ".bmp"
        elif "GIF" in filter_string:
            return ".gif"
        return ""

    # Method to reveal data from an image
    def steganography_decode(self):
        # Step 1: Select the image file that contains hidden data
        image_path, _ = QFileDialog.getOpenFileName(self, "Select Image", "", "Image Files (*.png *.jpg *.jpeg *.bmp *.gif)")
        if not image_path:
            QMessageBox.warning(self, "Input Error", "No image selected.")
            return


        try:
            # Step 2: Decode the hidden data from the image
            hidden_data = self.steganography_decode_method(image_path)
            if hidden_data:
                QMessageBox.information(self, "Retrieved Data", f"Hidden Data: {hidden_data}")
            else:
                QMessageBox.warning(self, "No Hidden Data", "No data found in the image.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred while decoding the data: {str(e)}")
    def steganography_decode_method(self, image_path):
        """Decode the hidden text data from the image."""
        img = Image.open(image_path)
        width, height = img.size

        binary_data = ""

        pixels = img.load()

        # Iterate through the image pixels to extract hidden data
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                # Extract the LSB of the red channel
                binary_data += str(r & 1)

        # Convert the binary data to text (ASCII)
        hidden_text = ""
        for i in range(0, len(binary_data), 8):
            byte = binary_data[i:i+8]
            if len(byte) == 8:
               hidden_text += chr(int(byte, 2))  # Convert binary to character

        return hidden_text if hidden_text else None
    
    # Method to verify a file
    def file_verify(self):
        selected_file = self.file_dropdown.currentText()
        if not selected_file:
            QMessageBox.warning(self, "Input Error", "Please select a file for verification.")
            return

        file_path = os.path.join(self.current_directory, selected_file)
        if not os.path.exists(file_path):
            QMessageBox.critical(self, "File Error", f"File '{file_path}' does not exist.")
            return

        # Step 1: Ask user to choose the verification method
        method, ok = QInputDialog.getItem(
            self,
            "File Verification",
            "Choose verification method:",
            ["SHA256 Hash", "MD5 Hash", "File Size"],
            0,
            False,
        )
        if not ok:
            return

        # Step 2: Handle verification based on the selected method
        if method == "SHA256 Hash":
            expected_hash, ok = QInputDialog.getText(self, "SHA256 Verification", "Enter expected SHA256 hash:")
            if ok and expected_hash:
                if self.verify_sha256(file_path, expected_hash):
                    QMessageBox.information(self, "Verification Result", "File is verified successfully (SHA256).")
                else:
                    QMessageBox.warning(self, "Verification Result", "File verification failed (SHA256).")
            else:
                QMessageBox.warning(self, "Input Error", "Invalid SHA256 hash entered.")

        elif method == "MD5 Hash":
            expected_hash, ok = QInputDialog.getText(self, "MD5 Verification", "Enter expected MD5 hash:")
            if ok and expected_hash:
                if self.verify_md5(file_path, expected_hash):
                    QMessageBox.information(self, "Verification Result", "File is verified successfully (MD5).")
                else:
                    QMessageBox.warning(self, "Verification Result", "File verification failed (MD5).")
            else:
                QMessageBox.warning(self, "Input Error", "Invalid MD5 hash entered.")

        elif method == "File Size":
            expected_size, ok = QInputDialog.getInt(self, "File Size Verification", "Enter expected file size (in bytes):")
            if ok:
                if self.verify_file_size(file_path, expected_size):
                    QMessageBox.information(self, "Verification Result", "File size matches successfully.")
                else:
                    QMessageBox.warning(self, "Verification Result", "File size mismatch.")
            else:
                QMessageBox.warning(self, "Input Error", "Invalid file size entered.")

    # Helper methods for verification

    def verify_sha256(self, file_path, expected_hash):
        """Verify file integrity using SHA256 hash."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as file:
                for block in iter(lambda: file.read(4096), b""):
                    sha256_hash.update(block)
            return sha256_hash.hexdigest() == expected_hash
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error during SHA256 verification: {str(e)}")
            return False

    def verify_md5(self, file_path, expected_hash):
        """Verify file integrity using MD5 hash."""
        md5_hash = hashlib.md5()
        try:
            with open(file_path, "rb") as file:
                for block in iter(lambda: file.read(4096), b""):
                    md5_hash.update(block)
            return md5_hash.hexdigest() == expected_hash
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error during MD5 verification: {str(e)}")
            return False

    def verify_file_size(self, file_path, expected_size):
        """Verify file size matches the expected size."""
        try:
            actual_size = os.path.getsize(file_path)
            return actual_size == expected_size
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error during file size verification: {str(e)}")
            return False

    # Method to save a key
    def key_library(self):
    # Step 1: Get the key to save
        key, ok = QInputDialog.getText(self, "Key Library", "Enter the key to save:")
        if not ok or not key:
           QMessageBox.warning(self, "Input Error", "Please enter a valid key.")
           return

    # Step 2: Get the reference name for the key
        reference_name, ok = QInputDialog.getText(self, "Reference Name", "Enter a reference name for the key:")
        if not ok or not reference_name:
            QMessageBox.warning(self, "Input Error", "Please enter a valid reference name.")
            return

    # Step 3: Ask user for save location
        save_path, _ = QFileDialog.getSaveFileName(self, "Save Key", f"{reference_name}.txt", "Text Files (*.txt)")
        if not save_path:
            QMessageBox.warning(self, "Save Error", "No save location selected.")
            return

    # Step 4: Save the key with the reference name in the .txt file
        try:
            with open(save_path, 'w', encoding='utf-8') as file:
                 file.write(f"Reference Name: {reference_name}\n")
                 file.write(f"Key: {key}\n")
            QMessageBox.information(self, "Success", f"Key saved successfully at {save_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred while saving the key: {str(e)}")

    # Method to sanitize data
    def sanitize_data(self):
        # Ask the user if they want to sanitize text input or a file
        choice, ok = QInputDialog.getItem(self, "Sanitize Data", "Choose an option:", ["Sanitize Text", "Sanitize File"], 0, False)

        if not ok:
            return  # Exit if the user cancels

        if choice == "Sanitize Text":
            # Sanitize Text Input
            input_data, ok = QInputDialog.getText(self, "Sanitize Text", "Enter data to sanitize:")
            if ok and input_data:
                sanitized_data = re.sub(r'[^\w\s]', '', input_data)  # Remove special characters
                sanitized_data = " ".join(sanitized_data.split())  # Trim whitespace
                sanitized_data = unicodedata.normalize('NFKD', sanitized_data).encode('ascii', 'ignore').decode('utf-8')  # Normalize Unicode
                QMessageBox.information(self, "Sanitized Data", f"Sanitized Data: {sanitized_data}")
            else:
                QMessageBox.warning(self, "Input Error", "Please enter valid data to sanitize.")

        elif choice == "Sanitize File":
            # Sanitize File Input
            file_path, _ = QFileDialog.getOpenFileName(self, "Select Text File", "", "Text Files (*.txt)")
            if not file_path:
                QMessageBox.warning(self, "File Selection Error", "No file selected!")
                return

            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()

                # Apply sanitization
                sanitized_content = re.sub(r'[^\w\s]', '', content)  # Remove special characters
                sanitized_content = " ".join(sanitized_content.split())  # Trim whitespace
                sanitized_content = unicodedata.normalize('NFKD', sanitized_content).encode('ascii', 'ignore').decode('utf-8')  # Normalize Unicode

                save_path, _ = QFileDialog.getSaveFileName(self, "Save Sanitized File", os.path.splitext(file_path)[0] + "_sanitized.txt", "Text Files (*.txt)")
                if save_path:
                    with open(save_path, 'w', encoding='utf-8') as sanitized_file:
                        sanitized_file.write(sanitized_content)
                    QMessageBox.information(self, "Success", f"Sanitized file saved at: {save_path}")
                else:
                    QMessageBox.warning(self, "Save Error", "Sanitized file not saved.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")
    # Method to zip a file
    # Method to zip a folder
    def zip_file(self):
        source_dir = QFileDialog.getExistingDirectory(self, "Select Directory to Zip")
        if source_dir:
            # Save file dialog with .zip as the only option
            output_file, _ = QFileDialog.getSaveFileName(
                self, "Save Zip File", "", "ZIP Files (*.zip)"
            )
            if output_file:
                # Ensure the file has the .zip extension
                if not output_file.endswith('.zip'):
                    output_file += '.zip'

                # Call the method to zip the directory with progress tracking
                if self.zip_file_zip_with_progress(source_dir, output_file):
                    QMessageBox.information(None, "Success", "Directory zipped successfully.")
                else:
                    QMessageBox.warning(None, "Error", "An error occurred while zipping the directory.")

    def zip_file_zip_with_progress(self, source_dir, output_file):
        try:
            # Count the total number of files to zip
            total_files = sum(len(files) for _, _, files in os.walk(source_dir))
            
            # Initialize a progress dialog
            progress_dialog = QProgressDialog("Zipping files...", "Cancel", 0, total_files, None)
            progress_dialog.setWindowTitle("Zipping Progress")
            progress_dialog.setMinimumDuration(0)
            progress_dialog.setValue(0)

            # Zipping logic with progress updates
            with zipfile.ZipFile(output_file, mode='w', compression=zipfile.ZIP_DEFLATED) as archive:
                file_count = 0
                for root, dirs, files in os.walk(source_dir):
                    for file in files:
                        # Update progress dialog
                        if progress_dialog.wasCanceled():
                            return False
                        file_count += 1
                        progress_dialog.setValue(file_count)
                        progress_dialog.setLabelText(f"Zipping: {file}")
                        
                        # Add file to archive
                        file_path = os.path.join(root, file)
                        archive_path = os.path.relpath(file_path, source_dir)
                        archive.write(file_path, arcname=archive_path)

            # Ensure progress bar is complete
            progress_dialog.setValue(total_files)
            return True
        except Exception as e:
            print(f"Error during zipping: {e}")
            return False
    # Method to unzip a file
    def unzip_file(self):
        # File dialog filter for .zip and .7z files
        zip_file, _ = QFileDialog.getOpenFileName(
            self, "Select Archive File", "", "Archive Files (*.7z *.zip)"
        )
        
        if zip_file:
            # Validate the file extension
            file_extension = os.path.splitext(zip_file)[1].lower()
            if file_extension not in ['.7z', '.zip']:
                QMessageBox.warning(self, "Error", "Please select a valid archive file (.7z or .zip).")
                return

            output_dir = QFileDialog.getExistingDirectory(self, "Select Output Directory")
            if output_dir:
                if file_extension == '.7z':
                    self.unzip_file_7z(zip_file, output_dir)
                elif file_extension == '.zip':
                    self.unzip_file_zip(zip_file, output_dir)
                QMessageBox.information(self, "Success", "Archive file extracted successfully.")

    # Method to unzip a 7z file
    def unzip_file_7z(self, zip_file, output_dir):
        with py7zr.SevenZipFile(zip_file, mode='r') as archive:
            archive.extractall(path=output_dir)

    # Method to unzip a zip file
    def unzip_file_zip(self, zip_file, output_dir):
        with zipfile.ZipFile(zip_file, mode='r') as archive:
            archive.extractall(path=output_dir)

    # Method to unzip a 7z file using py7zr
    def unzip_file_7zip(self, zip_file, output_dir):
        with py7zr.SevenZipFile(zip_file, mode='r') as archive:
            archive.extractall(path=output_dir)

    # Method to save a file
    def save_file(self):
        selected_file = self.file_dropdown.currentText()
        if selected_file:
            file_path = os.path.join(self.current_directory, selected_file)
            with open(file_path, "rb") as f:
                data = f.read()
            # Save logic here
            QMessageBox.information(self, "Success", "File saved successfully.")
        else:
            QMessageBox.warning(self, "Input Error", "Please select a file to save.")

    # Method to save a file as
    def save_as_file(self):
        selected_file = self.file_dropdown.currentText()
        if selected_file:
            file_path = QFileDialog.getSaveFileName(self, "Save File As", "", "All Files (*)")[0]
            if file_path:
                with open(file_path, "wb") as f:
                    data = b"Sample data"  # Replace with actual data to save
                    f.write(data)
                QMessageBox.information(self, "Success", "File saved successfully.")
        else:
            QMessageBox.warning(self, "Input Error", "Please select a file to save as.")
    def init_menu_bar(self):
        """Initialize the menu bar with a Preferences option."""
        menu_bar = QMenuBar(self)
        self.setMenuBar(menu_bar)

        # Preferences menu
        preferences_menu = menu_bar.addMenu("Settings")
        preferences_action = QAction("Preferences", self)
        preferences_action.triggered.connect(self.open_preferences)
        preferences_menu.addAction(preferences_action)

    def show_preference(self):
        dialog = PreferenceDialog()
        dialog.themeChanged.connect(self.change_theme)  # Connect the signal to change the theme
        dialog.exec()

    def change_theme(self, theme):
        """Change the theme based on the signal emitted from PreferenceDialog."""
        if theme == "light":
            self.setStyleSheet("background-color: white; color: black;")
        elif theme == "dark":
            self.setStyleSheet("background-color: #2d2d2d; color: white;")
        else:
            self.setStyleSheet("")  # Default theme (device default)
def main():
    app = QApplication(sys.argv)

    # Splash Screen
    splash = SplashScreen()
    splash.show()

    # Main App
    main_app = AdvancedEncryptorApp()

    # Timer for Splash Screen
    QTimer.singleShot(1000, lambda: (splash.close(), main_app.show()))

    sys.exit(app.exec())

if __name__ == "__main__":
    main()


    # Other methods remain unchanged...


import customtkinter as ctk
from tkinter import filedialog, messagebox  # สำหรับเลือกไฟล์ (integrate กับ CTk)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
from hashlib import sha256

# ฟังก์ชัน PKCS7 Padding/Unpadding (สำหรับทั้ง text และ file)
def pad(data):
    padder = padding.PKCS7(128).padder()  # 128 bits = 16 bytes
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def unpad(data):
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data

# ฟังก์ชันเข้ารหัส AES (universal สำหรับ bytes)
def encrypt(data, key):
    iv = os.urandom(16)  # IV สุ่ม
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pad(data)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  # รวม IV ด้านหน้า

# ฟังก์ชันถอดรหัส AES
def decrypt(ciphertext, key):
    iv = ciphertext[:16]  # แยก IV
    actual_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    plaintext = unpad(padded_plaintext)
    return plaintext

# GUI Class
class AESFileEncryptorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("AES File/Text Encryptor/Decryptor")
        self.geometry("600x700")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Tabview สำหรับแยกโหมด Text/File
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(pady=10, padx=10, fill="both", expand=True)

        # Tab 1: Text Mode
        self.text_tab = self.tabview.add("Text Mode")
        self.setup_text_tab()

        # Tab 2: File Mode
        self.file_tab = self.tabview.add("File Mode")
        self.setup_file_tab()

        # ช่องคีย์ (แชร์ทั้งสอง tab)
        self.key_label = ctk.CTkLabel(self, text="Key (32 bytes in Hex, 64 chars):", font=ctk.CTkFont(size=14))
        self.key_label.pack(pady=5)
        self.key_entry = ctk.CTkEntry(self, width=500, placeholder_text="e.g., 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        self.key_entry.pack(pady=5)

        # สถานะ (แชร์)
        self.status_label = ctk.CTkLabel(self, text="พร้อมใช้งาน", text_color="green")
        self.status_label.pack(pady=5)
        
        
#=================================================================================================================


    def setup_text_tab(self):
        # ช่อง input text
        self.text_input_label = ctk.CTkLabel(self.text_tab, text="Input (Plaintext for Encrypt / Hex for Decrypt):")
        self.text_input_label.pack(pady=5)
        self.text_input = ctk.CTkTextbox(self.text_tab, width=550, height=100)
        self.text_input.pack(pady=5)

        # ปุ่ม Text Encrypt/Decrypt
        self.text_btn_frame = ctk.CTkFrame(self.text_tab)
        self.text_btn_frame.pack(pady=10)
        self.text_encrypt_btn = ctk.CTkButton(self.text_btn_frame, text="Encrypt Text", command=self.do_text_encrypt, width=250)
        self.text_encrypt_btn.pack(side=ctk.LEFT, padx=10)
        self.text_decrypt_btn = ctk.CTkButton(self.text_btn_frame, text="Decrypt Text", command=self.do_text_decrypt, width=250)
        self.text_decrypt_btn.pack(side=ctk.RIGHT, padx=10)

        # ช่อง output text
        self.text_output_label = ctk.CTkLabel(self.text_tab, text="Output (Hex for Encrypt / Text for Decrypt):")
        self.text_output_label.pack(pady=5)
        self.text_output = ctk.CTkTextbox(self.text_tab, width=550, height=100)
        self.text_output.pack(pady=5)
        self.text_output.configure(state="disabled")

    def setup_file_tab(self):
        # ช่อง input file path
        self.file_input_label = ctk.CTkLabel(self.file_tab, text="Input File:")
        self.file_input_label.pack(pady=5)
        self.file_input_frame = ctk.CTkFrame(self.file_tab)
        self.file_input_frame.pack(pady=5)
        self.file_input_entry = ctk.CTkEntry(self.file_input_frame, width=450, placeholder_text="เลือกไฟล์...")
        self.file_input_entry.pack(side=ctk.LEFT, padx=5)
        self.browse_btn = ctk.CTkButton(self.file_input_frame, text="Browse", command=self.browse_input_file, width=80)
        self.browse_btn.pack(side=ctk.RIGHT, padx=5)

        # ปุ่ม File Encrypt/Decrypt
        self.file_btn_frame = ctk.CTkFrame(self.file_tab)
        self.file_btn_frame.pack(pady=10)
        self.file_encrypt_btn = ctk.CTkButton(self.file_btn_frame, text="Encrypt File", command=self.do_file_encrypt, width=250)
        self.file_encrypt_btn.pack(side=ctk.LEFT, padx=10)
        self.file_decrypt_btn = ctk.CTkButton(self.file_btn_frame, text="Decrypt File", command=self.do_file_decrypt, width=250)
        self.file_decrypt_btn.pack(side=ctk.RIGHT, padx=10)

        # ช่อง output file path (สำหรับ save)
        self.file_output_label = ctk.CTkLabel(self.file_tab, text="Output File (จะบันทึกอัตโนมัติ):")
        self.file_output_label.pack(pady=5)
        self.file_output_entry = ctk.CTkEntry(self.file_tab, width=550, placeholder_text="จะแสดง path ที่บันทึก")
        self.file_output_entry.pack(pady=5)

    def browse_input_file(self):
        filename = filedialog.askopenfilename(title="เลือกไฟล์ที่จะเข้ารหัส/ถอดรหัส")
        if filename:
            self.file_input_entry.delete(0, "end")
            self.file_input_entry.insert(0, filename)

    # Text Mode Functions
    def do_text_encrypt(self):
        try:
            plaintext = self.text_input.get("1.0", "end-1c").encode('utf-8')
            
            key_input = self.key_entry.get().strip().encode('utf-8')
            key = sha256(key_input).digest()
            
            encrypted = encrypt(plaintext, key)
            output = encrypted.hex()
            self.text_output.configure(state="normal")
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", output)
            self.text_output.configure(state="disabled")
            self.status_label.configure(text="เข้ารหัส text สำเร็จ!", text_color="green")
        except Exception as e:
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", f"Error: {str(e)}")
            self.status_label.configure(text="เกิดข้อผิดพลาดใน text mode", text_color="red")

    def do_text_decrypt(self):
        try:
            ciphertext_hex = self.text_input.get("1.0", "end-1c").strip()
            
            key_input = self.key_entry.get().strip().encode('utf-8')
            key = sha256(key_input).digest()
            
            ciphertext = bytes.fromhex(ciphertext_hex)
            decrypted = decrypt(ciphertext, key)
            output = decrypted.decode('utf-8')
            self.text_output.configure(state="normal")
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", output)
            self.text_output.configure(state="disabled")
            self.status_label.configure(text="ถอดรหัส text สำเร็จ!", text_color="green")
        except Exception as e:
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", f"Error: {str(e)}")
            self.status_label.configure(text="เกิดข้อผิดพลาดใน text mode", text_color="red")

    # File Mode Functions
    def do_file_encrypt(self):
        try:
            input_path = self.file_input_entry.get().strip()
            if not input_path or not os.path.exists(input_path):
                raise ValueError("เลือกไฟล์ input ที่ถูกต้อง")
            key_hex = self.key_entry.get().strip()
            if len(key_hex) != 64:
                raise ValueError("คีย์ต้องเป็น hex 64 ตัวอักษร (32 bytes)")
            key = bytes.fromhex(key_hex)

            # อ่านไฟล์เป็น bytes
            with open(input_path, 'rb') as f:
                data = f.read()

            # เข้ารหัส
            encrypted_data = encrypt(data, key)

            # สร้าง output path (เติม _encrypted)
            base, ext = os.path.splitext(input_path)
            output_path = f"{base}_encrypted{ext}"

            # บันทึกไฟล์
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)

            self.file_output_entry.delete(0, "end")
            self.file_output_entry.insert(0, output_path)
            self.status_label.configure(text=f"เข้ารหัสไฟล์สำเร็จ! บันทึกที่: {output_path}", text_color="green")
            messagebox.showinfo("สำเร็จ", f"ไฟล์เข้ารหัสบันทึกที่: {output_path}")
        except Exception as e:
            self.file_output_entry.delete(0, "end")
            self.file_output_entry.insert(0, f"Error: {str(e)}")
            self.status_label.configure(text="เกิดข้อผิดพลาดใน file mode", text_color="red")
            messagebox.showerror("ข้อผิดพลาด", str(e))

    def do_file_decrypt(self):
        try:
            input_path = self.file_input_entry.get().strip()
            if not input_path or not os.path.exists(input_path):
                raise ValueError("เลือกไฟล์ input ที่ถูกต้อง")
            key_hex = self.key_entry.get().strip()
            if len(key_hex) != 64:
                raise ValueError("คีย์ต้องเป็น hex 64 ตัวอักษร (32 bytes)")
            key = bytes.fromhex(key_hex)

            # อ่านไฟล์ encrypted (รวม IV)
            with open(input_path, 'rb') as f:
                ciphertext = f.read()

            # ถอดรหัส
            decrypted_data = decrypt(ciphertext, key)

            # สร้าง output path (เติม _decrypted)
            base, ext = os.path.splitext(input_path)
            output_path = f"{base}_decrypted{ext}"

            # บันทึกไฟล์
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)

            self.file_output_entry.delete(0, "end")
            self.file_output_entry.insert(0, output_path)
            self.status_label.configure(text=f"ถอดรหัสไฟล์สำเร็จ! บันทึกที่: {output_path}", text_color="green")
            messagebox.showinfo("สำเร็จ", f"ไฟล์ถอดรหัสบันทึกที่: {output_path}")
        except Exception as e:
            self.file_output_entry.delete(0, "end")
            self.file_output_entry.insert(0, f"Error: {str(e)}")
            self.status_label.configure(text="เกิดข้อผิดพลาดใน file mode", text_color="red")
            messagebox.showerror("ข้อผิดพลาด", str(e))

if __name__ == "__main__":
    app = AESFileEncryptorApp()
    app.mainloop()
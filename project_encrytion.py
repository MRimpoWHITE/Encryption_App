import customtkinter as ctk
from tkinter import filedialog, messagebox  # สำหรับเลือกไฟล์ (integrate กับ CTk)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
from hashlib import sha256

#AES ต้องเข้ารหัสข้อมูลทีละ 16 byte (128 bit)
# ฟังก์ชัน PKCS7 Padding/Unpadding (สำหรับทั้ง text และ file)
def pad(data):  #เติม padding 
    padder = padding.PKCS7(128).padder()  # 128 bits = 16 bytes
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def unpad(data):  #เอา padding ออก
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data

# ฟังก์ชันเข้ารหัส AES (universal สำหรับ bytes)
def encrypt(data, key): # key มีจำนวน 32 byte
    iv = os.urandom(16) #iv สุ่ม 16 ไบต์   และจะสุ่มใหม่ทุกครั้ง
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encrytor()
    padded_data = pad(data) #เติม padding ก่อน
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext #แปะ iv ไว้ข้างหน้า คืนค่า iv + ciphertext


def decrypt(ciphertext, key):
    iv = ciphertext[:16] # ดึง รอ 16 byte แรก
    actual_ciphertext = ciphertext[16:] # ที่เหลือคือ ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    plaintext = unpad(padded_plaintext)
    return plaintext

class AESFileEncryptorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("AES File/Text Encryptor/Decryptor") #หัวโปรแกรม
        self.geometry("600x700") #ขนาดหน้าต่าง
        ctk.set_appearance_mode("dark")         #ธีมโปรแกรม
        ctk.set_default_color_theme("blue")
        
        # Tabview สำหรับแยกโหมด Text/File
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(pady=10 ,padx=10, fill="both", expand=True)
        
        # Tab 1 : หน้าเข้ารหัสตัวหนังสือ Text Mode
        self.text_tab = self.tabview.add("Text Mode")
        self.setup_text_tab()
        
        # Tab 2 : หน้าอัปโหลดไฟล์ File Mode
        self.file_tab = self.tabview.add("File Mode")
        self.setup_file_tab()
        
        # ช่องคีย์ ใส่รหัส (โชว์ทั้ง 2 หน้าต่าง)
        self.key_label = ctk.CTkLabel(self, text="Key (32 bytes in Hex, 64 Chars):", font=ctk.CTkFont(size=14))
        self.key_label.pack(pady=5)
        
        # สถานะ พร้อมใช้หรือไม่ (โชว์ทั้ง 2 หน้าต่าง)
        self.status_label = ctk.CTkLabel(self, text="Ready To Go", text_color="green")
        self.status_label.pack(pady=5)
        
#========================== หน้าเข้ารหัสข้อความ =======================================================================
        

    def setup_text_tab(self):
        # ช่อง input text
        self.text_input_label = ctk.CTkLabel(self.text_tab, text="Input (Plaintext for Encrypt / Hex for Decrypt):")
        self.text_input_label.pack(pady=5)
        self.text_input = ctk.CTkTextbox(self.text_tab, width=550, height=100)
        self.text_input.pack(pady=5)
        
        # ปุ่ม Text Encrypt/Decrypt
        self.text_btn_frame = ctk.CTkFrame(self.text_tab)
        self.text_btn_frame.pack(pady=10)
        #ปุ่ม เข้ารหัสข้อความ Text Encrypt
        self.text_encrypt_btn = ctk.CTkButton(self.text_btn_frame, text="Encrypt Text", command=self.do_text_encrypt, width=250)
        self.text_encrypt_btn.pack(side=ctk.LEFT, padx=10)
        #ปุ่มถอดรหัสข้อความ Text Decrypt
        self.text_decrypt_btn = ctk.CTkButton(self.text_btn_frame, text="Decrypt Text", command=self.do_text_decrypt, width=250)
        self.text_decrypt_btn.pack(side=ctk.RIGHT, padx=10)
        
        # ช่อง output text 
        self.text_output_label = ctk.CTkLabel(self.text_tab, text="Output (Hex for Encrypt / Text for Decrypt):")
        self.text_output_label.pack(pady=5)
        self.text_output = ctk.CTkTextbox(self.text_tab, width=550, height=100)
        self.text_output.pack(pady=5)
        self.text_output.configure(state="disabled")  # ตั้งค่าให้อ่านได้อย่างเดียว
        
#========================== หน้าเข้ารหัสไฟบ์ =======================================================================
        
    def setup_file_tab(self):
        # ช่องเลือกไฟล์ 
        self.file_input_label = ctk.CTkLabel(self.file_tab, text="Input File To Encrypt / Decrypt:") # ชื่อ header
        self.file_input_label.pack(pady=5)
        self.file_input_frame = ctk.CTkFrame(self.file_tab)
        self.file_input_frame.pack(pady=5)
        
        self.file_input_entry = ctk.CTkEntry(self.file_input_frame, width=450, placeholder_text="Select file...")
        self.file_input_entry.pack(side=ctk.LEFT, padx=5)
        #ปุ่มเพื่อกดเลือกไฟล์
        self.browse_btn = ctk.CTkButton(self.file_input_frame, text="Browse", command=self.browse_input_file, width=80)
        self.browse_btn.pack(side=ctk.RIGHT, padx=5)
        
        
#================== ทำต่อตรงนี้

        
    def browse_input_file(self):
        filename = filedialog.askopenfilename(title="Select File To Encrypt / Decrypt ")
        if filename:
            self.file_input_entry.delete(0, "end")
            self.file_input_entry.insert(0, filename)

def do_text_encrypt(self):
    try:
        plaintext = self.text_input.get("1.0", "end-1c").encode('utf-8')
        key_hex = self.key_entry.get().strip()
        if len(key_hex) != 64:
            raise ValueError("Key must have 64 (32 bytes)")
        key = bytes.fromhex(key_hex)
        encrypted = encrypt(plaintext, key)
        output = encrypted.hex()
        self.text_output.delete("1.0", "end")
        self.text_output.insert("1.0", output)
        

#เริ่มตัวโปรแกรม
if __name__ == "__main__":
    app = AESFileEncryptorApp()
    app.mainloop()
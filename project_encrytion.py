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
    encryptor = cipher.encryptor()
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
        self.key_label = ctk.CTkLabel(self, text="Input Password : ", font=ctk.CTkFont(size=14))
        self.key_label.pack(pady=5)
        self.key_entry = ctk.CTkEntry(self, width=500, placeholder_text="e.g., mypassword123 , 12345678 ")
        self.key_entry.pack(pady=5)
        
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
        # ช่องเลือกไฟล์
        self.file_input_entry = ctk.CTkEntry(self.file_input_frame, width=450, placeholder_text="Select file...")
        self.file_input_entry.pack(side=ctk.LEFT, padx=5)
        #ปุ่มเพื่อกดเลือกไฟล์
        self.browse_btn = ctk.CTkButton(self.file_input_frame, text="Browse", command=self.browse_input_file, width=80)
        self.browse_btn.pack(side=ctk.RIGHT, padx=5)
        
        # ปุ่ม Text Encrypt/Decrypt
        self.file_btn_frame = ctk.CTkFrame(self.file_tab)
        self.file_btn_frame.pack(pady=5)
        #ปุ่ม เข้ารหัสข้อความ Text Encrypt
        self.file_encrypt_btn = ctk.CTkButton(self.file_btn_frame, text="Encrypt File", command=self.do_file_encrypt, width=250)
        self.file_encrypt_btn.pack(side=ctk.LEFT, padx=10)
        #ปุ่มถอดรหัสข้อความ Text Decrypt
        self.file_decrypt_btn = ctk.CTkButton(self.file_btn_frame, text="Decrypt File", command=self.do_file_decrypt, width=250)
        self.file_decrypt_btn.pack(side=ctk.RIGHT, padx=10) 
        
        #ช่อง output สำหรับไฟล์ file path (สำหรับ save)
        self.file_output_label = ctk.CTkLabel(self.file_tab, text="Output File (Auto save next to original File):")
        self.file_output_label.pack(pady=5)
        
        self.file_output_entry = ctk.CTkEntry(self.file_tab, width=550, placeholder_text="Will show the path that save the file here")
        self.file_output_entry.pack(pady=5)
        self.text_output.configure(state="disabled")
        
#==================================================================================
        
    def browse_input_file(self):
        filename = filedialog.askopenfilename(title="Select File To Encrypt / Decrypt ")
        if filename:
            self.file_input_entry.delete(0, "end")
            self.file_input_entry.insert(0, filename)

#================ ฟังค์ชั่นเข้ารหัสข้อความ ====================================================================


    def do_text_encrypt(self):
        try:
            plaintext = self.text_input.get("1.0", "end-1c").encode('utf-8')
            #รหัสสำหรับใช้เข้าหรือถอดรหัสไฟล์
            key_input = self.key_entry.get().strip().encode('utf-8')
            key = sha256(key_input).digest() # ได้ key 32 bytes อัตโนมัติ
            
            encrypted = encrypt(plaintext, key)
            output = encrypted.hex()
            self.text_output.configure(state="normal")
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", output)
            self.text_output.configure(state="disabled")
            
            self.status_label.configure(text="Successfully Encrypted text!!", text_color="Green")
            
        except Exception as e: # หากเกิด Error
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", f"Error: {str(e)}")
            self.status_label.configure(text="There is an Error with text mode", text_color="red")
            
#================ ฟังค์ชั่นถอดรหัสข้อความ ====================================================================
            
    def do_text_decrypt(self):
        try:
            ciphertext_hex = self.text_input.get("1.0", "end-1c").strip()
            #รหัสสำหรับใช้เข้าหรือถอดรหัสไฟล์
            key_input = self.key_entry.get().strip().encode('utf-8')
            key = sha256(key_input).digest() # ได้ key 32 bytes อัตโนมัติ
            
            ciphertext = bytes.fromhex(ciphertext_hex)
            decrypted = decrypt(ciphertext, key)
            
            output = decrypted.decode('utf-8')
            self.text_output.configure(state="normal")
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", output)
            self.text_output.configure(state="disabled")
            
            self.status_label.configure(text="Successfully Decrypted text!", text_color="green")
            
        except Exception as e:# หากเกิด Error
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", f"Error: {str(e)}")
            self.status_label.configure(text="There is an Error with text mode", text_color="red")
        
#================ ฟังค์ชั่นเข้ารหัสไฟล์ ====================================================================

    def do_file_encrypt(self):
        try:
            input_path = self.file_input_entry.get().strip()
            if not input_path or not os.path.exists(input_path):
                raise ValueError("Please Correct Input File")    
           
            #รหัสสำหรับใช้เข้าหรือถอดรหัสไฟล์
            key_input = self.key_entry.get().strip().encode('utf-8')
            key = sha256(key_input).digest()
            
            # อ่านไฟล์เป็น bytes
            with open(input_path, 'rb') as f:
                data = f.read()   
                
            # เข้ารหัส
            encrypted_data = encrypt(data, key)
            
            # สร้าง output path (เติม _encrypted ข้างหลัง)
            base, ext = os.path.splitext(input_path)
            output_path = f"{base}_encrypted{ext}"
            
            # # สร้าง output path (เติม encrypted_ ข้างหน้า)
            # dirname = os.path.dirname(input_path)
            # filename = os.path.basename(input_path)
            # output_path = os.path.join(dirname, f"Encrypted_{filename}")
            
            # บันทึกไฟล์ เขียนไฟล์ output path
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            self.text_output.configure(state="normal")
            self.file_output_entry.delete(0, "end")
            self.file_output_entry.insert(0, output_path)
            self.text_output.configure(state="disabled")
            
            self.status_label.configure(text=f"Successfully Encrypted File..! Path : {output_path}", text_color="green")
            messagebox.showinfo("Success", f"Encrypted File Path : {output_path}")
    
        except Exception as e:  # หากเกิด Error
            self.file_output_entry.delete(0, "end")
            self.file_output_entry.insert(0, f"Errror: {str(e)}")
            self.status_label.configure(text="There is an Error in File Mode", text_color="red")
            messagebox.showerror("Error Found", str(e))
            
#================ ฟังค์ชั่นถอดรหัสไฟล์ ====================================================================
            
    def do_file_decrypt(self):
        try:
            input_path = self.file_input_entry.get().strip()
            if not input_path or not os.path.exists(input_path):
                raise ValueError("Please Correct Input File")
            
            #รหัสสำหรับใช้เข้าหรือถอดรหัสไฟล์
            key_input = self.key_entry.get().strip().encode('utf-8')
            key = sha256(key_input).digest()
            
            # อ่านไฟล encrypted (รวม iv)
            with open(input_path, 'rb') as f:
                ciphertext = f.read()
                
            # ถอดรหัสไฟล์
            decrypted_data = decrypt(ciphertext, key)
            
            # # สร้าง output path (เติม _decrypted ข้างหลัง)
            # base, ext = os.path.splitext(input_path)
            # output_path = f"{base}_decrypted{ext}"
            
            # # สร้าง output path (เติม decrypted_ ข้างหน้า)
            # dirname = os.path.dirname(input_path)
            # filename = os.path.basename(input_path) 
            # output_path = os.path.join(dirname, f"Decrypted_{filename}")      
            
            dirname = os.path.dirname(input_path)
            filename = os.path.basename(input_path)
            #แยกชื่อไฟล์และนามสกุล
            base, ext = os.path.splitext(filename)
            # ลบ _encrypted ถ้ามี
            if base.endswith('_encrypted'):
                base = base[:-len('_encrypted')]
            # เติม _decrypted
            output_path = os.path.join(dirname, f"{base}_decrypted{ext}")      
            
            # บันทึกไฟล์
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            self.text_output.configure(state="normal")
            self.file_output_entry.delete(0, "end")
            self.file_output_entry.insert(0, output_path)
            self.text_output.configure(state="disabled")
            
            self.status_label.configure(text=f"Successfully Decrypted File..! Path : {output_path}", text_color="green")
            messagebox.showinfo("Success", f"Decrypted File Path : {output_path}")
            
        
        except Exception as e: # หากเกิด Error
            self.file_output_entry.delete(0, "end")
            self.file_output_entry.insert(0, f"Errror: {str(e)}")
            self.status_label.configure(text="There is an Error in File Mode", text_color="red")
            messagebox.showerror("Error Found", str(e))

#เริ่มตัวโปรแกรม
if __name__ == "__main__":
    app = AESFileEncryptorApp()
    app.mainloop()
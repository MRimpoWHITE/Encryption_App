import customtkinter as ctk
from tkinter import filedialog, messagebox  
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

#AES ต้องเข้ารหัสข้อมูลทีละ 16 byte (128 bit)
def pad(data):  #เติม padding 
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def unpad(data):  #เอา padding ออก
    unpadder = padding.PKCS7(128).unpadder()
    padded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data

def encrypt(data, key): # key มีจำนวน 32 byte
    iv = os.urandom(16) #iv สุ่ม 16 ไบต์   และจะสุ่มใหม่ทุกครั้ง
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encrytor()
    padded_data = pad(data) #เติม padding ก่อน
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext #แปะ iv ไว้ข้างหน้า คืนค่า iv + ciphertext


    
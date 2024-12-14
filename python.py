#project
# This is a crypto project
#!/usr/bin/env python

# ----------------- Header Files ---------------------#

from __future__ import division, print_function, unicode_literals

import sys
import random
import argparse
import logging
from tkinter import *
import tkinter.filedialog
from tkinter import messagebox 
import os
from PIL import Image
import math
from Crypto.Cipher import AES
import hashlib
import binascii
import numpy as np

global password 

def load_image(name):
    return Image.open(name)

# ----------------- Functions for encryption ---------------------#
def prepare_message_image(image, size):
    if size != image.size:
        image = image.resize(size, Image.ANTIALIAS)
    return image

def generate_secret(size, secret_image=None):
    width, height = size
    new_secret_image = Image.new(mode="RGB", size=(width * 2, height * 2))

    for x in range(0, 2 * width, 2):
        for y in range(0, 2 * height, 2):
            color1 = np.random.randint(255)
            color2 = np.random.randint(255)
            color3 = np.random.randint(255)
            new_secret_image.putpixel((x,  y),   (color1, color2, color3))
            new_secret_image.putpixel((x+1, y),   (255-color1, 255-color2, 255-color3))
            new_secret_image.putpixel((x,  y+1), (255-color1, 255-color2, 255-color3))
            new_secret_image.putpixel((x+1, y+1), (color1, color2, color3))
                
    return new_secret_image

def generate_ciphered_image(secret_image, prepared_image):
    width, height = prepared_image.size
    ciphered_image = Image.new(mode="RGB", size=(width * 2, height * 2))
    for x in range(0, width * 2, 2):
        for y in range(0, height * 2, 2):
            sec = secret_image.getpixel((x, y))
            msssg = prepared_image.getpixel((int(x/2), int(y/2)))
            color1 = (msssg[0] + sec[0]) % 256
            color2 = (msssg[1] + sec[1]) % 256
            color3 = (msssg[2] + sec[2]) % 256
            ciphered_image.putpixel((x,  y),   (color1, color2, color3))
            ciphered_image.putpixel((x+1, y),   (255-color1, 255-color2, 255-color3))
            ciphered_image.putpixel((x,  y+1), (255-color1, 255-color2, 255-color3))
            ciphered_image.putpixel((x+1, y+1), (color1, color2, color3))
                
    return ciphered_image

def generate_image_back(secret_image, ciphered_image):
    width, height = secret_image.size
    new_image = Image.new(mode="RGB", size=(int(width / 2), int(height / 2)))
    for x in range(0, width, 2):
        for y in range(0, height, 2):
            sec = secret_image.getpixel((x, y))
            cip = ciphered_image.getpixel((x, y))
            color1 = (cip[0] - sec[0]) % 256
            color2 = (cip[1] - sec[1]) % 256
            color3 = (cip[2] - sec[2]) % 256
            new_image.putpixel((int(x/2),  int(y/2)),   (color1, color2, color3))
               
    return new_image

#------------------------Encryption -------------------#
def level_one_encrypt(Imagename):
    message_image = load_image(Imagename)
    size = message_image.size

    secret_image = generate_secret(size)
    secret_image.save("secret.jpeg")

    prepared_image = prepare_message_image(message_image, size)
    ciphered_image = generate_ciphered_image(secret_image, prepared_image)
    ciphered_image.save("2-share_encrypt.jpeg")

# -------------------- Construct Encrypted Image  ----------------#
def construct_enc_image(ciphertext, relength, width, height):
    asciicipher = binascii.hexlify(ciphertext).decode()
    def replace_all(text, dic):
        for i, j in dic.items():
            text = text.replace(i, j)
        return text

    # Use replace function to replace ASCII cipher characters with numbers
    reps = {'a':'1', 'b':'2', 'c':'3', 'd':'4', 'e':'5', 'f':'6'}
    asciiciphertxt = replace_all(asciicipher, reps)

    # Construct encrypted image
    step = 3
    encimageone = [asciiciphertxt[i:i+step] for i in range(0, len(asciiciphertxt), step)]
    # Ensure valid RGB triplet
    if len(encimageone[-1]) < step:
        encimageone[-1] += "0" * (step - len(encimageone[-1]))
    while len(encimageone) % 3 != 0:
        encimageone.append("101")

    encimagetwo = [(int(encimageone[i]), int(encimageone[i+1]), int(encimageone[i+2])) for i in range(0, len(encimageone), 3)]
    while len(encimagetwo) > relength:
        encimagetwo.pop()

    encim = Image.new("RGB", (int(width), int(height)))
    encim.putdata(encimagetwo)
    encim.save("visual_encrypt.jpeg")

#------------------------- Visual-encryption -------------------------#
def encrypt(imagename, password):
    plaintext = []
    plaintextstr = ""

    im = Image.open(imagename)
    pix = im.load()

    width, height = im.size
    
    for y in range(height):
        for x in range(width):
            plaintext.append(pix[x, y])

    for i in range(len(plaintext)):
        for j in range(3):
            plaintextstr += str(plaintext[i][j] + 100).zfill(3)

    relength = len(plaintext)
    plaintextstr += f"h{height}hw{width}w"

    while len(plaintextstr) % 16 != 0:
        plaintextstr += "n"

    obj = AES.new(password, AES.MODE_CBC, b'This is an IV456')
    ciphertext = obj.encrypt(plaintextstr.encode('utf-8'))

    cipher_name = f"{imagename}.crypt"
    with open(cipher_name, 'wb') as g:
        g.write(ciphertext)

    construct_enc_image(ciphertext, relength, width, height)
    level_one_encrypt("visual_encrypt.jpeg")
    

# ---------------------- Decryption ---------------------- #
def decrypt(ciphername, password):
    secret_image = Image.open("secret.jpeg")
    ima = Image.open("2-share_encrypt.jpeg")
    new_image = generate_image_back(secret_image, ima)
    new_image.save("2-share_decrypt.jpeg")

    with open(ciphername, 'rb') as cipher:
        ciphertext = cipher.read()

    obj2 = AES.new(password, AES.MODE_CBC, b'This is an IV456')
    decrypted = obj2.decrypt(ciphertext).decode('utf-8')
    decrypted = decrypted.replace("n", "")

    newwidth = int(decrypted.split("w")[1])
    newheight = int(decrypted.split("h")[1])

    heightr = f"h{newheight}h"
    widthr = f"w{newwidth}w"
    decrypted = decrypted.replace(heightr, "").replace(widthr, "")

    step = 3
    finaltextone = [decrypted[i:i+step] for i in range(0, len(decrypted), step)]
    finaltexttwo = [(int(finaltextone[i]) - 100, int(finaltextone[i+1]) - 100, int(finaltextone[i+2]) - 100) for i in range(0, len(finaltextone), step)]

    newim = Image.new("RGB", (newwidth, newheight))
    newim.putdata(finaltexttwo)
    newim.save("visual_decrypt.jpeg")

# --------------------- GUI starts here ---------------------
def pass_alert():
    messagebox.showinfo("Password Alert", "Please enter a password.")

def enc_success(imagename):
    messagebox.showinfo("Success", "Encrypted Image: " + imagename)

def image_open():
    global file_path_e
    enc_pass = passg.get()
    if not enc_pass:
        pass_alert()
    else:
        password = hashlib.sha256(enc_pass.encode()).digest()
        filename = tkinter.filedialog.askopenfilename()
        file_path_e = os.path.dirname(filename)
        encrypt(filename, password)

def cipher_open():
    global file_path_d
    dec_pass = passg.get()
    if not dec_pass:
        pass_alert()
    else:
        password = hashlib.sha256(dec_pass.encode()).digest()
        filename = tkinter.filedialog.askopenfilename()
        file_path_d = os.path.dirname(filename)
        decrypt(filename, password)

class App:
    def __init__(self, master):
        global passg
        title = "Image Encryption"
        author = "Made by RAHUL SIDDU RAGHU"
        msgtitle = Message(master, text=title)
        msgtitle.config(font=('helvetica', 17, 'bold'), width=200)
        msgauthor = Message(master, text=author)
        msgauthor.config(font=('helvetica', 10), width=200)

        canvas_width = 200
        canvas_height = 50
        w = Canvas(master, width=canvas_width, height=canvas_height)
        msgtitle.pack()
        msgauthor.pack()
        w.pack()

        passg = Entry(master, show="*", width=20)
        passg.pack()

        self.encrypt = Button(master, text="Encrypt", fg="black", command=image_open, width=25, height=5)
        self.encrypt.pack(side=LEFT)
        self.decrypt = Button(master, text="Decrypt", fg="black", command=cipher_open, width=25, height=5)
        self.decrypt.pack(side=RIGHT)

# ------------------ MAIN -------------#
root = Tk()
root.wm_title("Image Encryption")
app = App(root)
root.mainloop()


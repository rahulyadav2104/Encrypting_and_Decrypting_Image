# Encrypting_and_Decrypting_Image
Certainly! I’ll explain the key sections of the image encryption code in simple terms, line by line, or grouped where necessary for clarity

Header Files
python
Copy code
from __future__ import division, print_function, unicode_literals
Ensures compatibility between Python 2 and 3 for division, printing, and Unicode handling.
python
Copy code
import sys, random, argparse, logging
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
These libraries provide:
Tkinter: For the GUI (Graphical User Interface).
Pillow (PIL): For image manipulation.
AES from Crypto.Cipher: For encryption and decryption.
hashlib: To generate secure hashes (used for encryption keys).
binascii: To handle binary and ASCII conversions.
numpy: To work with random numbers for generating the secret image.
Load Image
python
Copy code
def load_image(name):
    return Image.open(name)
Opens an image file (e.g., .jpg or .png) for manipulation.
Image Processing Functions
Resize and Prepare Message Image
python
Copy code
def prepare_message_image(image, size):
    if size != image.size:
        image = image.resize(size, Image.ANTIALIAS)
    return image
Checks if the input image needs resizing. If yes, resizes it to the specified size.
Generate Secret Image
python
Copy code
def generate_secret(size, secret_image=None):
    width, height = size
    new_secret_image = Image.new(mode="RGB", size=(width * 2, height * 2))
Creates a blank "secret image" twice the width and height of the input image.
python
Copy code
for x in range(0, 2 * width, 2):
    for y in range(0, 2 * height, 2):
        color1 = np.random.randint(255)
        color2 = np.random.randint(255)
        color3 = np.random.randint(255)
Loops through every 2x2 block of pixels in the blank image.
Generates random RGB values (0-255) for a pixel.
python
Copy code
new_secret_image.putpixel((x,  y),   (color1, color2, color3))
new_secret_image.putpixel((x+1, y),   (255-color1, 255-color2, 255-color3))
new_secret_image.putpixel((x,  y+1), (255-color1, 255-color2, 255-color3))
new_secret_image.putpixel((x+1, y+1), (color1, color2, color3))
Fills each 2x2 block with contrasting RGB values (one pixel gets a color, others get its inverse).
python
Copy code
return new_secret_image
Returns the created secret image.
Combine Secret and Prepared Image
python
Copy code
def generate_ciphered_image(secret_image, prepared_image):
    width, height = prepared_image.size
    ciphered_image = Image.new(mode="RGB", size=(width * 2, height * 2))
Creates another blank image (ciphered image) for storing encrypted data.
python
Copy code
for x in range(0, width * 2, 2):
    for y in range(0, height * 2, 2):
        sec = secret_image.getpixel((x, y))
        msssg = prepared_image.getpixel((int(x/2), int(y/2)))
Loops through every 2x2 block of the secret image.
Retrieves the corresponding pixel from the prepared input image.
python
Copy code
color1 = (msssg[0] + sec[0]) % 256
color2 = (msssg[1] + sec[1]) % 256
color3 = (msssg[2] + sec[2]) % 256
Adds the RGB values of the secret and input image pixels, wrapping around if they exceed 255.
python
Copy code
ciphered_image.putpixel((x,  y),   (color1, color2, color3))
ciphered_image.putpixel((x+1, y),   (255-color1, 255-color2, 255-color3))
ciphered_image.putpixel((x,  y+1), (255-color1, 255-color2, 255-color3))
ciphered_image.putpixel((x+1, y+1), (color1, color2, color3))
Fills the 2x2 block in the ciphered image with the new values and their complements.
python
Copy code
return ciphered_image
Returns the completed ciphered image.
AES Encryption
python
Copy code
def encrypt(imagename, password):
    plaintext = []
    plaintextstr = ""
Initializes a list and string to store pixel data.
Extract and Transform Pixel Data
python
Copy code
im = Image.open(imagename) 
pix = im.load()

width, height = im.size

for y in range(height):
    for x in range(width):
        plaintext.append(pix[x, y])
Loads the input image, retrieves pixel data, and adds each pixel (RGB tuple) to plaintext.
python
Copy code
for i in range(len(plaintext)):
    for j in range(3):
        plaintextstr += str(plaintext[i][j] + 100).zfill(3)
Converts each RGB value into a 3-digit string (e.g., 100 for 0).
Add Metadata and Padding
python
Copy code
relength = len(plaintext)
plaintextstr += f"h{height}hw{width}w"

while len(plaintextstr) % 16 != 0:
    plaintextstr += "n"
Adds image dimensions to the string and ensures its length is a multiple of 16 (required by AES).
Perform Encryption
python
Copy code
obj = AES.new(password, AES.MODE_CBC, b'This is an IV456')
ciphertext = obj.encrypt(plaintextstr.encode('utf-8'))
Creates an AES encryption object using the password and a fixed Initialization Vector (IV).
Encrypts the padded plaintext.
Save Ciphertext
python
Copy code
cipher_name = f"{imagename}.crypt"
with open(cipher_name, 'wb') as g:
    g.write(ciphertext)
Saves the encrypted data to a file.
Decryption
The decryption process reverses the encryption:

Reads the ciphertext file.
Decrypts it using the same AES key and IV.
Extracts dimensions and pixel data from the decrypted plaintext.
Reconstructs the original image.
GUI Code
The GUI is built using Tkinter:

Buttons: Encrypt and Decrypt.
Password Entry: Ensures the user provides a password.
File Dialogs: Allow the user to select files for encryption or decryption.

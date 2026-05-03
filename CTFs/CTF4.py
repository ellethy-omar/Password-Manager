# python3.14 CTF4.py

import skimage.io as io
import numpy as np
import re

class Steganography:

    def __init__(self) -> None:
        img = io.imread("assets/stego.png")
        self.img_np = np.array(img)

    def flatten_img(self, img):
        return img.flatten()

    def format_pixel_binary(self, flatten):
        return np.array(["{:08b}".format(n) for n in flatten])

    def lsb_1_extract(self, img):
        return np.array(["{}".format(n[-1:]) for n in img])

    def lsb_2_extract(self, img):
        return np.array(["{}".format(n[-2:]) for n in img])

    def join_bits(self, arr):
        return "".join(arr)

    def chunck_bytes(self, arr):
        return [arr[i : i + 8] for i in range(0, len(arr), 8)]

    def form_message(self, chuncks):
        message = ""
        for byte in chuncks:
            ascii = int(byte, 2)
            if ascii == 0:
                break
            message += chr(ascii)
            
        return message
            
    def isGibberesh(self, msg):
        pattern = re.compile(r"[^\x20-\x7E]")
        return pattern.findall(msg)
    
    def run_steganography(self):
        flatten = self.flatten_img(self.img_np)
        binary_pixels = self.format_pixel_binary(flatten)
        
        lsb1 = self.lsb_1_extract(binary_pixels) 
        lsb2 = self.lsb_2_extract(binary_pixels) 
        
        lsb1_joined = self.join_bits(lsb1)
        lsb2_joined = self.join_bits(lsb2)
        
        lsb1_chuncked = self.chunck_bytes(lsb1_joined)
        lsb2_chuncked = self.chunck_bytes(lsb2_joined)
        
        lsb1_msg = self.form_message(lsb1_chuncked)
        lsb2_msg = self.form_message(lsb2_chuncked)
        
        if not self.isGibberesh(lsb1_msg):
            print("Correct Message: ", lsb1_msg)
        
        if not self.isGibberesh(lsb2_msg):
            print("Correct Message: ", lsb2_msg)
            
if __name__ == "__main__":
    st = Steganography()
    st.run_steganography()
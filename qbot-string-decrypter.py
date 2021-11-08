import idc
import idautils
from idaapi import *
import idaapi
import ida_nalt

 
 
def image_base():
     imagebase = ida_nalt.get_imagebase()
     print(imagebase)
     return imagebase
 

base = image_base()

def decrypt_string_core(index, key, enc_data):
    decrypted_data = ""
    while True:
        key_byte = idc.get_wide_byte(key + index ) 
        enc_byte = idc.get_wide_byte(enc_data +(index % 0x5A))
        decrypted_byte =  key_byte ^ enc_byte
        decrypted_data += chr(decrypted_byte)
        index += 1
        if decrypted_byte == 0:
            break
        if index > 10000:
            break
    return str(decrypted_data)

def get_cross_refs(function_address):
    cross_refs_list =[]
    for ref in idautils.XrefsTo(function_address):
      print("[+] function cross ref found -->" ,hex(ref.frm))
      cross_refs_list.append((ref.frm))
    return  cross_refs_list

def decrypt_string_range_1(index=0xE4C):        
 decrypted_string =  decrypt_string_core(index, base+0x1D5A8, base+0x1E3F8)
 print("[+] Decrypted string is --->" , decrypted_string )
 return decrypted_string    

def decrypt_string_range_2(index=0x4F3):   
 decrypted_string =  decrypt_string_core(index, base+0x1D0B0, base+0x1D050)
 print("[+] Decrypted string is --->" , decrypted_string )
 return decrypted_string  

def get_decrypt_string_index(ref_address):
    ea = (ref_address)
    (index) = idaapi.get_arg_addrs(ref_address)
    print("[+] Index ebp key found at address --->", index)
    key = idc.get_operand_value(index[0], 0)
    if (key  == 1) or (key == 0x4):
     key = idc.get_operand_value(index[0], 1)   
     print("[+] possible index key is ---> ",  hex(key ))
     return hex(key)
    else:
    
     print("[+] possible index key is ---> ",  hex(key) )
     return hex(key)


def start_decryption(function_address, range):
     function_references  = get_cross_refs(function_address) 
     for address in function_references:
      print("[+] processing address ---> ", hex(address) )
      key = get_decrypt_string_index((address))
      #decrypt_string_A((keyindex, 16))
      if range == 1:
       dec_string = decrypt_string_range_1(int(key, 16))
       #set decrypted string as comment
       idc.set_cmt(address, dec_string, 0)
      if range == 2:
       dec_string = decrypt_string_range_2(int(key, 16))
       #set decrypted string as comment
       idc.set_cmt(address, dec_string, 0)
          

  

 
def main_decryption(decryption_functions):
 try:  
  for function, range in decryption_functions:
   start_decryption(function, range) 
 except Exception as decryption_error:
     print("[-] Failed to prefrom decryption consider revising the functions and encrypted data addresses")
 
 
if __name__ == "__main__":
    decryption_functions = [(base+0x95A8,1) ,(base+0x95C2,1) , (base+0x1080,2), (base+0x109A,2)]
    main_decryption(decryption_functions)
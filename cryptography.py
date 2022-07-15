#!/usr/bin/env python3
# coding: utf-8

# In[1]:


import sys, math
from os import urandom
from pathlib import Path
from time inport time_ns
from timeit import default_timer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# ### Reading Files from the current path.

# In[2]:



SF_1KB = Path('Sample_File_1KB.txt')
if not SF_1KB.is_file():
    print('The sample file %s is not found' % (SF_1KB))
    sys.exit()
    
SF_10MB = Path('Sample_File_10MB.txt')
if not SF_10MB.is_file():
    print('The sample file %s is not found' % (SF_10MB))
    sys.exit()
    
SF_1MB = Path('Sample_File_1MB.txt')
if not SF_1MB.is_file():
    print('The file %s does not exist' % (SF_1MB))
    sys.exit()

open_file_1KB = open(SF_1KB)
Data_1KB = open_file_1KB.read()

open_file_10MB = open(SF_10MB)
Data_10MB = open_file_10MB.read()

open_file_1MB = open(SF_1MB)
Data_1MB = open_file_1MB.read()


# ### (a) AES implementation in CBC-Mode using 128-bit key.

# In[3]:


print("(a) AES implementation in CBC-Mode using 128-bit key.\n")

#Creation of 128-bit AES-key.
start_AES_CBC_key =time_ns()
key = urandom(16)
end_AES_CBC_key = time_ns()
time_taken=end_AES_CBC_key-start_AES_CBC_key
print('\tTime taken for generating new AES 128-bit Key: %.10f nano seconds\n' %(time_taken))


#Padding data with respect to current block size.
def pad_data(data,block_size):
    padder = padding.PKCS7(block_size*8).padder()
    return padder.update(data) + padder.finalize()


#Unpadding data with respect to current block size.
def unpad_data(data,block_size):
    unpadder = padding.PKCS7(block_size*8).unpadder()
    return unpadder.update(data) + unpadder.finalize()



def AES_CBC_128(data):

    #Input data.
    data = data
    block_size=len(key)
    
    #Encrypting data in the file.
    start_AES_CBC_Enc = time_ns()
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    
    encrypt_handler = cipher.encryptor()
    cipher_text = encrypt_handler.update(pad_data(data, block_size)) + encrypt_handler.finalize()
    end_AES_CBC_Enc = time_ns() 
    
    cipher_size = sys.getsizeof(cipher_text)
    total_enc_time=end_AES_CBC_Enc-start_AES_CBC_Enc
    enc_speed_per_byte = total_enc_time/cipher_size
       

    #Decrypting data in the file.
    start_AES_CBC_Dec = time_ns()
    decrypt_handler = cipher.decryptor()
    plain_text=unpad_data(decrypt_handler.update(cipher_text) + decrypt_handler.finalize(), block_size)
    end_AES_CBC_Dec = time_ns()
    
    plain_text_size = sys.getsizeof(plain_text)
    total_dec_time=end_AES_CBC_Dec-start_AES_CBC_Dec
    dec_speed_per_byte = total_dec_time/plain_text_size
    

    #Valiating above cryptographic approach.
    if plain_text == data:
        print("\tEncryption is successful.")
        print("\t\tTotal time taken for encrypting data is: %.10f nano seconds" %(total_enc_time))
        print("\t\tTotal time taken for decrypting data is: %.10f nano seconds" %(total_dec_time))
        print("\t\tEncryption speed per byte is: %.10f nano seconds" %(enc_speed_per_byte))   
        print("\t\tDecryption speed per byte is: %.10f nano seconds" %(dec_speed_per_byte))    
        
    else:
        print("Enryption has failed.")


        
#calling out cryptographic functions for each of the files.       
print("\tFile:  ",SF_1KB,)
AES_CBC_128(bytes(Data_1KB, encoding='utf-8'))

print("\n")

print("\tFile:  ",SF_10MB,)
AES_CBC_128(bytes(Data_10MB, encoding='utf-8'))

print("\n\n")


# ### (b) AES implementation in CTR-Mode using 128-bit key.

# In[4]:


print("(b) AES implementation in CTR-Mode using 128-bit key.\n")

# Creation of 128-bit AES-key.
start_AES_CTR_key =time_ns()
key = urandom(16)
end_AES_CTR_key = time_ns()
time_taken=end_AES_CTR_key-start_AES_CTR_key
print('\tTime taken for generating new AES-CTR 128-bit Key: %.10f nano seconds\n' %(time_taken))



def AES_CTR_128(data):
    
    # message input
    data = data
    block_size=len(key)
    
    # Encrypting data in the file.
    start_AES_CTR_Enc = time_ns()
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce=iv))
    
    encrypt_handler = cipher.encryptor()
    cipher_text = encrypt_handler.update(data) + encrypt_handler.finalize()
    end_AES_CTR_Enc = time_ns() 
    
    cipher_size = sys.getsizeof(cipher_text)
    total_enc_time=end_AES_CTR_Enc-start_AES_CTR_Enc
    enc_speed_per_byte = total_enc_time/cipher_size       

    
    #Decrypting data in the file.
    start_AES_CTR_Dec = time_ns()
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce=iv))
    decrypt_handler = cipher.decryptor()
    plain_text=decrypt_handler.update(cipher_text) + decrypt_handler.finalize()
    end_AES_CTR_Dec = time_ns()
    
    plain_text_size = sys.getsizeof(plain_text)
    total_dec_time=end_AES_CTR_Dec-start_AES_CTR_Dec
    dec_speed_per_byte = total_dec_time/plain_text_size
    

    if plain_text == data:
        print("\tEncryption is successful.","\n")
        print("\t\tTotal time taken for encrypting data is: %.10f nano nano seconds" %(total_enc_time))
        print("\t\tTotal time taken for decrypting data is: %.10f nano nano seconds" %(total_dec_time))
        print("\t\tEncryption speed per byte is: %.10f nano nano seconds" %(enc_speed_per_byte))   
        print("\t\tDecryption speed per byte is: %.10f nano seconds" %(dec_speed_per_byte))    
    else:
        print("Enryption has failed.")

        
#calling out cryptographic functions for each of the files.        
print("\tFile:  ",SF_1KB,)
AES_CTR_128(bytes(Data_1KB, encoding='utf-8'))

print("\n")

print("\tFile:  ",SF_10MB,)
AES_CTR_128(bytes(Data_10MB, encoding='utf-8'))


print("\n\n")


# ### (c) AES implementation in CTR-Mode using 256-bit key.

# In[5]:


print("(c) AES implementation in CTR-Mode using 256-bit key.\n")

# Creation of 256-bit AES-key.
start_AES_CTR_key =time_ns()
key = urandom(32)
end_AES_CTR_key = time_ns()
time_taken=end_AES_CTR_key-start_AES_CTR_key
print('\tTime taken for generating new AES-CTR 256-bit Key: %.10f nano seconds\n' %(time_taken))



def AES_CTR_256(data):
    
    # message input
    data = data
    block_size=len(key)
    
    # Encrypting data in the file.
    start_AES_CTR_Enc = time_ns()
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce=iv))
    
    encrypt_handler = cipher.encryptor()
    cipher_text = encrypt_handler.update(data) + encrypt_handler.finalize()
    end_AES_CTR_Enc = time_ns() 
    
    cipher_size = sys.getsizeof(cipher_text)
    total_enc_time=end_AES_CTR_Enc-start_AES_CTR_Enc
    enc_speed_per_byte = total_enc_time/cipher_size       

    
    #Decrypting data in the file.
    start_AES_CTR_Dec = time_ns()
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce=iv))
    decrypt_handler = cipher.decryptor()
    plain_text=decrypt_handler.update(cipher_text) + decrypt_handler.finalize()
    end_AES_CTR_Dec = time_ns()
    
    plain_text_size = sys.getsizeof(plain_text)
    total_dec_time=end_AES_CTR_Dec-start_AES_CTR_Dec
    dec_speed_per_byte = total_dec_time/plain_text_size
    

    if plain_text == data:
        print("\tEncryption is successful.","\n")
        print("\t\tTotal time taken for encrypting data is: %.10f nano seconds" %(total_enc_time))
        print("\t\tTotal time taken for decrypting data is: %.10f nano seconds" %(total_dec_time))
        print("\t\tEncryption speed per byte is: %.10f nano seconds" %(enc_speed_per_byte))   
        print("\t\tDecryption speed per byte is: %.10f nano seconds" %(dec_speed_per_byte))    
    else:
        print("Enryption has failed.")

        
#calling out cryptographic functions for each of the files.        
print("\tFile:  ",SF_1KB,)
AES_CTR_256(bytes(Data_1KB, encoding='utf-8'))

print("\n")

print("\tFile:  ",SF_10MB,)
AES_CTR_256(bytes(Data_10MB, encoding='utf-8'))


print("\n\n")


# ### (d) RSA implementation with PKCS #1 v2 padding-OAEP using 2048-bit key.

# In[6]:


print("(d) RSA implementation with PKCS #1 v2 padding-OAEP using 2048-bit key.\n")

# Creation of 2048-bit RSA-key.
start_RSA_2048_key =time_ns()
private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048,backend=default_backend())
public_key = private_key.public_key()
end_RSA_2048_key = time_ns()
time_taken=end_RSA_2048_key-start_RSA_2048_key
print('\tTime taken for generating new RSA 2048-bit Key: %.10f nano seconds\n' %(time_taken))


def RSA_OAEP_2048(data):
    
    #Input data.
    data = data
    data_length = len(data)
    chunk_size = int((2048/8)-66)
    chunk_count=math.ceil(data_length/chunk_size)
    print("\tFor the data of length", data_length,",the computed chunk_size is",chunk_size,
          "bytes per each chunk and the total number of chunks are", chunk_count,".")
    
    RSA_Failed=False
    total_enc_time =0
    total_dec_time =0
    i=0
        
    while i< chunk_count:
        
        current_data = data[chunk_size*i:chunk_size*(i+1)]

        #Encrypting data with public key.
        start_RSA_OAEP_Enc = time_ns()
        cipher_text = public_key.encrypt(current_data, 
                                         asymmetric.padding.OAEP(mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                                         algorithm=hashes.SHA256(),label=None))       
        end_RSA_OAEP_Enc = time_ns()
        total_enc_time = total_enc_time + (end_RSA_OAEP_Enc-start_RSA_OAEP_Enc)

        
        #Decrypting data with private key.
        start_RSA_OAEP_Dec = time_ns()
        plain_text = private_key.decrypt(cipher_text, 
                                         asymmetric.padding.OAEP(mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                                         algorithm=hashes.SHA256(),label=None))
        end_RSA_OAEP_Dec = time_ns()
        total_dec_time = total_dec_time + (end_RSA_OAEP_Dec-start_RSA_OAEP_Dec)

        if plain_text != current_data:
            RSA_Failed=True
            print("Enryption has failed.\n")
            break

        i+=1
        
        
    enc_speed_per_byte = total_enc_time/data_length
    dec_speed_per_byte = total_dec_time/data_length
    
    if not RSA_Failed:
        print("\tEncryption is successful.")
        print("\t\tTotal time taken for encrypting data is: %.10f nano seconds" %(total_enc_time))
        print("\t\tTotal time taken for decrypting data is: %.10f nano seconds" %(total_dec_time))
        print("\t\tEncryption speed per byte is: %.10f nano seconds" %(enc_speed_per_byte))   
        print("\t\tDecryption speed per byte is: %.10f nano seconds" %(dec_speed_per_byte)) 
        
        
        

print("\tFile:  ",SF_1KB,)
RSA_OAEP_2048(bytes(Data_1KB, encoding='utf-8'))

print("\n")

print("\tFile:  ",SF_1MB,)
RSA_OAEP_2048(bytes(Data_1MB, encoding='utf-8'))


print("\n\n")


# ### (e) RSA implementation with PKCS #1 v2 padding-OAEP using 3072-bit key.

# In[7]:


print("(e) RSA implementation with PKCS #1 v2 padding-OAEP using 3072-bit key.\n")

# Creation of 3072-bit RSA-key.
start_RSA_3072_key =time_ns()
private_key=rsa.generate_private_key(public_exponent=65537, key_size=3072,backend=default_backend())
public_key = private_key.public_key()
end_RSA_3072_key = time_ns()
time_taken=end_RSA_3072_key-start_RSA_3072_key
print('\tTime taken for generating new RSA 3072-bit Key: %.10f nano seconds\n' %(time_taken))


def RSA_OAEP_3072(data):
    
    #Input data.
    data = data
    data_length = len(data)
    chunk_size = int((3072/8)-66)
    chunk_count=math.ceil(data_length/chunk_size)
    print("\tFor the data of length", data_length,",the computed chunk_size is",chunk_size,
          "bytes per each chunk and the total number of chunks are", chunk_count,".")
    
    RSA_Failed=False
    total_enc_time =0
    total_dec_time =0
    i=0
        
    while i< chunk_count:
        
        current_data = data[chunk_size*i:chunk_size*(i+1)]

        #Encrypting data with public key.
        start_RSA_OAEP_Enc = time_ns()
        cipher_text = public_key.encrypt(current_data, 
                                         asymmetric.padding.OAEP(mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                                         algorithm=hashes.SHA256(),label=None))       
        end_RSA_OAEP_Enc = time_ns()
        total_enc_time = total_enc_time + (end_RSA_OAEP_Enc-start_RSA_OAEP_Enc)

        
        #Decrypting data with private key.
        start_RSA_OAEP_Dec = time_ns()
        plain_text = private_key.decrypt(cipher_text, 
                                         asymmetric.padding.OAEP(mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                                         algorithm=hashes.SHA256(),label=None))
        end_RSA_OAEP_Dec = time_ns()
        total_dec_time = total_dec_time + (end_RSA_OAEP_Dec-start_RSA_OAEP_Dec)

        if plain_text != current_data:
            RSA_Failed=True
            print("Enryption has failed.\n")
            break

        i+=1
        
        
    enc_speed_per_byte = total_enc_time/data_length
    dec_speed_per_byte = total_dec_time/data_length
    
    if not RSA_Failed:
        print("\tEncryption is successful.")
        print("\t\tTotal time taken for encrypting data is: %.10f nano seconds" %(total_enc_time))
        print("\t\tTotal time taken for decrypting data is: %.10f nano seconds" %(total_dec_time))
        print("\t\tEncryption speed per byte is: %.10f nano seconds" %(enc_speed_per_byte))   
        print("\t\tDecryption speed per byte is: %.10f nano seconds" %(dec_speed_per_byte)) 
        
        
        

print("\tFile:  ",SF_1KB,)
RSA_OAEP_3072(bytes(Data_1KB, encoding='utf-8'))

print("\n")

print("\tFile:  ",SF_1MB,)
RSA_OAEP_3072(bytes(Data_1MB, encoding='utf-8'))


print("\n\n")


# ### (f) Hash Function implementations - SHA-256, SHA-512, SHA3-256.

# In[8]:


print("(f) Hash Function implementations - SHA-256, SHA-512, SHA3-256.\n")

def Hash_SHA_256(data):  
    data_length=len(data)
    start_SHA_256 =time_ns()
    hash_data = hashes.Hash(hashes.SHA256())
    hash_data.update(data)
    hash_data.finalize()
    end_SHA_256 =time_ns()
    
    total_hash_time=end_SHA_256-start_SHA_256
    compute_per_byte = total_hash_time/data_length
    print('\t\tTime taken for computing hash value is:%.10f nano seconds' %(total_hash_time))
    print('\t\tHash Time per byte: %.10f nano seconds' %(compute_per_byte))  
    
    
def Hash_SHA_512(data):
    data_length=len(data)
    start_SHA_512 =time_ns()
    hash_data = hashes.Hash(hashes.SHA512())
    hash_data.update(data)
    hash_data.finalize()
    end_SHA_512 =time_ns()
    
    total_hash_time=end_SHA_512-start_SHA_512
    compute_per_byte = total_hash_time/data_length
    print('\t\tTime taken for computing hash value is:%.10f nano seconds' %(total_hash_time))
    print('\t\tHash Time per byte: %.10f nano seconds' %(compute_per_byte))  
    
    
    
def Hash_SHA3_256(data):
    data_length=len(data)
    start_SHA3_256 =time_ns()
    data=data
    hash_data = hashes.Hash(hashes.SHA3_256())
    hash_data.update(data)
    hash_data.finalize()
    end_SHA3_256 =time_ns()
    
    total_hash_time=end_SHA3_256-start_SHA3_256
    compute_per_byte = total_hash_time/data_length
    print('\t\tTime taken for computing hash value is:%.10f nano seconds' %(total_hash_time))
    print('\t\tHash Time per byte: %.10f nano seconds' %(compute_per_byte)) 
    
    
    
print("\tSHA-256 Function.")
print("\t\tFile:  ",SF_1KB,)
Hash_SHA_256(bytes(Data_1KB, encoding='utf-8'))

print("\n\t\tFile:  ",SF_10MB,)
Hash_SHA_256(bytes(Data_10MB, encoding='utf-8'))

print("\n")

print("\n\tSHA-512 Function.")
print("\t\tFile:  ",SF_1KB,)
Hash_SHA_512(bytes(Data_1KB, encoding='utf-8'))

print("\n\t\tFile:  ",SF_10MB,)
Hash_SHA_512(bytes(Data_10MB, encoding='utf-8'))
    
print("\n")

print("\n\tSHA3-256 Function.")
print("\t\tFile:  ",SF_1KB,)
Hash_SHA3_256(bytes(Data_1KB, encoding='utf-8'))

print("\n\t\tFile:  ",SF_10MB,)
Hash_SHA3_256(bytes(Data_10MB, encoding='utf-8'))

print("\n\n")


# ### (g) DSA implementation using 2048-bit key and SHA-256 hash function.

# In[9]:


print("(g) DSA implementation using 2048-bit key and SHA-256 hash function.\n")

# Creation of 2048-bit DSA-key.
start_DSA_2048_key =time_ns()
private_key = dsa.generate_private_key(key_size=2048,backend=default_backend())
public_key = private_key.public_key()
end_DSA_2048_key = time_ns()
time_taken=end_DSA_2048_key-start_DSA_2048_key
print("\tTime taken for generating new DSA 2048-bit Key: %.10f nano seconds\n" %(time_taken))


def DSA_2048(data):
    
    #Input data
    data=data
    data_length=len(data)
    
    #Producing Signature.
    start_DSA_Sign_2048 = time_ns()
    signature = private_key.sign(data,hashes.SHA256())
    end_DSA_Sign_2048 = time_ns()
    time_taken_to_sign=end_DSA_Sign_2048-start_DSA_Sign_2048
    compute_per_byte_to_sign = time_taken_to_sign/data_length
    print("\t\tTime taken for producing signature on the file is: %.10f nano seconds" %(time_taken_to_sign))
    
    
    #Verifying Signature.
    start_DSA_Verify_2048 = time_ns()
    try:       
        public_key.verify(signature,data,hashes.SHA256())
        end_DSA_Verify_2048 = time_ns()
        
        time_taken_to_verify=end_DSA_Verify_2048-start_DSA_Verify_2048
        compute_per_byte_to_verify = time_taken_to_verify/data_length
        print('\t\tTime taken for verifying signature on the file:    %.10f nano seconds' %(time_taken_to_verify))
        print("\t\tCompute time per byte for signature is: %.10f nano seconds" %(compute_per_byte_to_sign))   
        print("\t\tCompute time per byte for verification is: %.10f nano seconds" %(compute_per_byte_to_verify))
        print("\t\tThe data is Authentic.")
        
    except:
        print("The data is not Authentic.")
        


print("\tFile:  ",SF_1KB,)
DSA_2048(bytes(Data_1KB, encoding='utf-8'))

print("\n")

print("\tFile:  ",SF_10MB,)
DSA_2048(bytes(Data_10MB, encoding='utf-8'))

print("\n\n")


# ### (h) DSA implementation using 3072-bit key and SHA-256 hash function.

# In[10]:


print("(h) DSA implementation using 3072-bit key and SHA-256 hash function.\n")

# Creation of 3072-bit DSA-key.
start_DSA_3072_key =time_ns()
private_key = dsa.generate_private_key(key_size=3072,backend=default_backend())
public_key = private_key.public_key()
end_DSA_3072_key = time_ns()
time_taken=end_DSA_3072_key-start_DSA_3072_key
print("\tTime taken for generating new DSA 3072-bit Key: %.10f nano seconds\n" %(time_taken))


def DSA_3072(data):
    
    #Input data
    data=data
    data_length=len(data)
    
    #Producing Signature.
    start_DSA_Sign_3072 = time_ns()
    signature = private_key.sign(data,hashes.SHA256())
    end_DSA_Sign_3072 = time_ns()
    time_taken_to_sign=end_DSA_Sign_3072-start_DSA_Sign_3072
    compute_per_byte_to_sign = time_taken_to_sign/data_length
    print("\t\tTime taken for producing signature on the file is: %.10f nano seconds" %(time_taken_to_sign))
    
    
    #Verifying Signature.
    start_DSA_Verify_3072 = time_ns()
    try:       
        public_key.verify(signature,data,hashes.SHA256())
        end_DSA_Verify_3072 = time_ns()
        
        time_taken_to_verify=end_DSA_Verify_3072-start_DSA_Verify_3072
        compute_per_byte_to_verify = time_taken_to_verify/data_length
        print('\t\tTime taken for verifying signature on the file:    %.10f nano seconds' %(time_taken_to_verify))
        print("\t\tCompute time per byte for signature is: %.10f nano seconds" %(compute_per_byte_to_sign))   
        print("\t\tCompute time per byte for verification is: %.10f nano seconds" %(compute_per_byte_to_verify))
        print("\t\tThe data is Authentic.")
        
    except:
        print("The data is not Authentic.")
        


print("\tFile:  ",SF_1KB,)
DSA_3072(bytes(Data_1KB, encoding='utf-8'))

print("\n")

print("\tFile:  ",SF_10MB,)
DSA_3072(bytes(Data_10MB, encoding='utf-8'))

print("\n\n")


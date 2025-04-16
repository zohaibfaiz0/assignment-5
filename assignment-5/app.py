import hashlib 
import json 
import streamlit as st 
from cryptography.fernet import Fernet  

# Generate a key for encryption 
key = Fernet.generate_key() 
cipher = Fernet(key)  

# File path to store encrypted data (JSON file) 
file_path = 'stored_data.json'  

# Load stored data from JSON file (if it exists) 
def load_data():     
    try:         
        with open(file_path, 'r') as file:             
            return json.load(file)     
    except (FileNotFoundError, json.JSONDecodeError):         
        return {}  

# Save data to the JSON file 
def save_data():     
    with open(file_path, 'w') as file:         
        json.dump(stored_data, file, indent=4)  

# In-memory storage for encrypted data 
stored_data = load_data()  

# Function to hash passkey 
def hash_key(passkey):     
    return hashlib.sha256(passkey.encode()).hexdigest()  

# Function to encrypt data 
def encrypt_data(text):     
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Store the encryption key in session state to preserve it between reruns
if 'encryption_key' not in st.session_state:
    st.session_state.encryption_key = key

# Streamlit UI Setup 
st.title("🔒 Secure Data Encryption System")  

# Menu navigation for different actions 
menu = ["Home", "Store Data", "Retrieve Data"] 
choice = st.sidebar.selectbox("Select an action", menu)  

# Handle the "Home" page 
if choice == "Home":     
    st.subheader("🏠 Welcome to the Secure Data System")     
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")  

# Handle the "Store Data" page 
elif choice == "Store Data":     
    st.subheader("📂 Store Data Securely")          
    
    # User inputs for data and passkey     
    user_data = st.text_area("Enter data to store:")     
    passkey = st.text_input("Enter a passkey:", type="password")          
    
    # Encrypt and store data when button is clicked     
    if st.button("Encrypt & Save"):         
        if user_data and passkey:             
            hashed_passkey = hash_key(passkey)             
            encrypted_text = encrypt_data(user_data)             
            stored_data[encrypted_text] = {                 
                "encrypted_data": user_data,                
                "hashed_key": hashed_passkey,             
            }             
            save_data()  # Save to JSON file             
            st.success("✅ Your data is stored securely!")             
            st.write("Encrypted Data:", encrypted_text)         
        else:             
            st.error("⚠️ Both data and passkey are required!")  

# Handle the "Retrieve Data" page 
elif choice == "Retrieve Data":     
    st.subheader("🔍 Retrieve Your Data")          
    
    # User inputs for encrypted data and passkey     
    input_encrypted = st.text_area("Enter the encrypted data:")     
    input_passkey = st.text_input("Enter the passkey:", type="password")          
    
    # Attempt to decrypt data when button is clicked     
    if st.button("Decrypt"):         
        if input_encrypted and input_passkey:             
            hashed_input_passkey = hash_key(input_passkey)                          
            
            # Check if the encrypted data exists and passkey matches             
            if input_encrypted in stored_data and stored_data[input_encrypted]["hashed_key"] == hashed_input_passkey:  
                # Get the original data directly from storage                
                original_data = stored_data[input_encrypted]["encrypted_data"]
                st.success(f"✅ Decrypted Data: {original_data}")
            else:                 
                st.error("❌ Invalid passkey or encrypted data.")         
        else:             
            st.error("⚠️ Both encrypted data and passkey are required!")
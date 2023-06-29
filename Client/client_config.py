import rsa
import os

if os.path.exists("pukey_client.pem") and os.path.exists("prkey_client.pem"):
    exit()

public_key, private_key = rsa.newkeys(512)

with open(f"pukey_client.pem", "wb") as f:
    f.write(public_key.save_pkcs1())

with open(f"prkey_client.pem", "wb") as f:
    f.write(private_key.save_pkcs1())
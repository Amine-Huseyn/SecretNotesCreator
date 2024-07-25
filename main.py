from tkinter import *
from tkinter import messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def saveandenc():
   title= title_entry.get()
   message= input_text.get("1.0", END)
   master_secret =master_secret_input.get()

   if len(title)==0 or len(message)==0 or len(master_secret)==0:
       messagebox.showinfo(title="ERROR",message="Please enter your info")
   else:
        message_encrypted= encode(master_secret,message)


        try:

            with open("mysecret.txt","a") as datafile:
               datafile.write(f"\n{title}\n{message_encrypted}")
        except FileNotFoundError:
            with open("mysecret.txt", "w") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')

        finally:
           title_entry.delete(0,END)
           master_secret_input.delete(0,END)
           input_text.delete("1.0" ,END)

def decrypt_notes():
    message_encrypted = input_text.get("1.0", END)
    master_secret = master_secret_input.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        try:
            decrypted_message = decode(master_secret,message_encrypted)
            input_text.delete("1.0", END)
            input_text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please make sure of encrypted info.")

#window
window =Tk()
window.title("Secret Notes")
window.minsize(width=400, height=800)
window.configure(background="#E5E5E5")

photo=PhotoImage(file="topsecret.png")
photolabel=Label(image=photo)
photolabel.place(x=160,y=50)


mylabel= Label(text="Enter your title", font=("Arial",15,"bold"))
mylabel.config(bg="#E5E5E5")
mylabel.place(x=130,y=170)

mylabel2= Label(text="Enter your secret", font=("Arial",15,"bold"))
mylabel2.config(bg="#E5E5E5")
mylabel2.place(x=120,y=240)

mylabel3=Label(text="Enter your master key", font=("Arial",15,"bold"))
mylabel3.config(bg="#E5E5E5")
mylabel3.place(x=90,y=610)

title_entry=Entry(width=35)
title_entry.place(x=100,y=210)

input_text=Text(width=40, height=20)
input_text.place(x=40,y=280)

master_secret_input=Entry(width=35)
master_secret_input.place(x=90,y=650)

savebutton=Button(text="Save & Encrypt",command=saveandenc)
savebutton.place(x=150,y=680)

decbutton=Button(text="Decrypt",command=decrypt_notes)
decbutton.place(x=168,y=710)

window.mainloop()
from tkinter import *
from Crypto.Cipher import AES

import os
import math
import random
import smtplib
import nmap
import requests
from torrequest import TorRequest
global screen3
def delete1():
  screen2.destroy()
def delete3():
  screen4.destroy()
def delete2():
  screen6.destroy()
def delete4():
  screen5.destroy()
def delete6():
  screen8.destroy()
def delete7():
  screen9.destroy()
def delete8():
  screen10.destroy()
def delete9():
  screen11.destroy()
def delete11():
  screen.destroy()
def delete12():
  screen3.destroy()
def otp_verify():
  global screen6
  screen6 = Toplevel(screen)
  screen6.title("Adiltgan tanih")
  screen6.geometry("300x250")
  Label(screen6, text = "Door medeellee oruulan nevterne uu").pack()
  Label(screen6, text = "").pack()
  global email_verify
  email_verify = StringVar()
  global email_entry
  Label(screen6, text = "Email * ").pack()
  email_entry1 = Entry(screen6, textvariable = email_verify)
  email_entry1.pack()
  Label(screen6, text = "").pack()
  Button(screen6, text = "OTP-iig ilgeeh", width = 10, height = 1, command = authentication_verify).pack()

def password_not_recognised():
  global screen4
  screen4 = Toplevel(screen)
  screen4.title("Amjilttai")
  screen4.geometry("150x100")
  Label(screen4, text = "Password buruu baina").pack()
  Button(screen4, text = "OK", command =delete3).pack()

def user_not_found():
  global screen5
  screen5 = Toplevel(screen)
  screen5.title("Amjilttai")
  screen5.geometry("150x100")
  Label(screen5, text = "Hereglegch oldsongui").pack()
  Button(screen5, text = "OK", command =delete4).pack()

  
def register_user():

  username_info = username.get()
  password_info = password.get()

  file=open(username_info, "w")
  file.write(username_info+"\n")
  file.write(password_info)
  file.close()

  username_entry.delete(0, END)
  password_entry.delete(0, END)

  Label(screen1, text = "Burtgel amjilttai", fg = "green" ,font = ("calibri", 11)).pack()

def login_verify():
  
  username1 = username_verify.get()
  password1 = password_verify.get()
  username_entry1.delete(0, END)
  password_entry1.delete(0, END)

  list_of_files = os.listdir()
  if username1 in list_of_files:
    file1 = open(username1, "r")
    verify = file1.read().splitlines()
    if password1 in verify:
        otp_verify()
        delete1()
    else:
        password_not_recognised()
        login()
  else:
        user_not_found()
        login()
def authentication_verify():
  global otp_verify
  otp_verify = StringVar()
  global otp_entry
  global email_entry1
  global OTP
  
  

  digits="0123456789"
  OTP=""
  for i in range(6):
      OTP+=digits[math.floor(random.random()*10)]
  otp = OTP + " is your OTP"
  msg= otp
  s = smtplib.SMTP('smtp.gmail.com', 587)
  s.starttls()
  s.login("tuvshuutuvshinjargal21@gmail.com", "ozvfqxakzzddbbva")
  emailid = email_verify.get()
  s.sendmail('&&&&&&&&&&&',emailid,msg)
  global screen10
  screen10 = Toplevel(screen)
  screen10.title("OTP -iig ilgeelee")
  screen10.geometry("150x100")
  Label(screen10, text = "OTP * ").pack()
  otp_entry1 = Entry(screen10, textvariable = otp_verify)
  otp_entry1.pack()
  Label(screen10, text = "").pack()
  Button(screen10, text = "OK", command = otp_ending1).pack()
def otp_ending1():
  
  otp_verify1 = otp_verify.get()
  if otp_verify1 == OTP:
      delete8()
      delete2()
      serving()
  else:
      error_screen()
def error_screen():
  global screen11
  screen11 = Toplevel(screen)
  screen11.title("ERROR !!!")
  screen11.geometry("150x100")
  Label(screen11, text = "OTP buruu baina").pack()
  Button(screen11, text = "OK", command =delete9).pack()
def geo_ip1():
  # !/usr/bin/env python3
  import socket
  from geolite2 import geolite2
  import argparse
  import json
  parser = argparse.ArgumentParser(description='Get IP Geolocation info')
  parser.add_argument('--hostname', action="store", dest="hostname", default='python.org')
  given_args = parser.parse_args()
  hostname = given_args.hostname
  ip_address = socket.gethostbyname(hostname)
  Label(screen14, text="IP address: {0}".format(ip_address)).pack()

  reader = geolite2.reader()
  response = reader.get(ip_address)
  Label(screen14, text = json.dumps(response, indent=4)).pack()
  Label(screen14, text=json.dumps(response['continent']['names']['en'], indent=4)).pack()
  Label(screen14, text=json.dumps(response['country']['names']['en'], indent=4)).pack()
  Label(screen14, text=json.dumps(response['location']['latitude'], indent=4)).pack()
  Label(screen14, text=json.dumps(response['location']['longitude'], indent=4)).pack()
  Label(screen14, text=json.dumps(response['location']['time_zone'], indent=4)).pack()
  print(json.dumps(response, indent=4))
  print("Continent:", json.dumps(response['continent']['names']['en'], indent=4))
  print("Country:", json.dumps(response['country']['names']['en'], indent=4))
  print("Latitude:", json.dumps(response['location']['latitude'], indent=4))
  print("Longitude:", json.dumps(response['location']['longitude'], indent=4))
  print("Time zone:", json.dumps(response['location']['time_zone'], indent=4))
def tor_network():
  global screen13
  screen13 = Toplevel(screen)
  screen13.title("TOR")
  screen13.geometry("600x350")
  Label(screen13, text="Tor suljeend holbogdoh").pack()
  Label(screen13, text="").pack()
  with TorRequest(proxy_port=9050, ctrl_port=9051, password=None) as tr:
    response = tr.get('http://ipecho.net/plain')
    Label(screen13, text=response.text).pack()

    Label(screen13, text=type(tr.ctrl)).pack()
    tr.ctrl.signal('CLEARDNSCACHE')

    tr.reset_identity()
    response = tr.get('http://httpbin.org/ip')
    Label(screen13, text=response.text).pack()

def nmapping():
  global screen12
  global h
  h = StringVar()
  global h_entry
  screen12 = Toplevel(screen)
  screen12.title("Nmap")
  screen12.geometry("600x400")
  Label(screen12, text="Scan hiih hostoo oruulna uu. Jishee ni: scanme.nmap.org").pack()
  Label(screen12, text="").pack()
  Label(screen12, text="Host").pack()
  h_entry1 = Entry(screen12, textvariable=h)
  h_entry1.pack()
  Button(screen12, text="OK", command=nmapping_function).pack()
def nmapping_function():
  h1 = h.get()
  portScanner = nmap.PortScanner()
  host_scan = h.get()
  portlist ="21,22,23,25,80"
  portScanner.scan(hosts=host_scan, arguments='-n -p'+portlist)
  Label(screen12, text=portScanner.command_line()).pack()
  hosts_list = [(x, portScanner[x]['status']['state']) for x in portScanner.all_hosts()]
  for host, status in hosts_list:
    Label(screen12, text=host).pack()
    Label(screen12, text=status).pack()
  for protocol in portScanner[host].all_protocols():
    Label(screen12, text='Protocol : %s' % protocol)
    listport = portScanner[host]['tcp'].keys()
    for port in listport:
      Label(screen12, text='Port : %s State : %s' % (port, portScanner[host][protocol][port]['state']))



def cryptograph():
  global screen11
  global k
  k = StringVar()
  global k_entry
  global ctext
  ctext = StringVar()
  global ctext_entry

  screen11 = Toplevel(screen)
  screen11.title("Shiferlelt")
  screen11.geometry("600x400")
  Label(screen11, text="Shiferlelt hiih text iig 32 bit urttai nuuts tulhuuriig 16 bit urttai oruulna uu. Jishee ni: nuuts_tulhuur123").pack()
  Label(screen11, text="").pack()

  Label(screen11, text="Key").pack()
  k_entry1 = Entry(screen11, textvariable=k)
  k_entry1.pack()
  Label(screen11, text="Message: ").pack()
  ctext_entry1 = Entry(screen11, textvariable=ctext)
  ctext_entry1.pack()
  Button(screen11, text="OK", command=cipher_function).pack()

def cipher_function():
  global key
  ctext1 = ctext.get()
  k1 = k.get()
  key = k.get()
  message = ctext.get().encode("utf8")
  encrypt_AES = AES.new(key.encode("utf8"), AES.MODE_CBC, 'This is an IV-12'.encode("utf8"))
  ciphertext = encrypt_AES.encrypt(message)

  decrypt_AES = AES.new(key.encode("utf8"), AES.MODE_CBC, 'This is an IV-12'.encode("utf8"))
  message_decrypted = decrypt_AES.decrypt(ciphertext)
  Label(screen11, text = "Shiferlelt hiigdsen text").pack()
  Label(screen11, text = ciphertext).pack()
  Label(screen11, text = "Decrypt hiigdsen text").pack()
  Label(screen11, text = message_decrypted.strip().decode()).pack()

def authentication_not_recognised():
  global screen8
  screen8 = Toplevel(screen)
  screen8.title("Amjiltgui")
  screen8.geometry("150x100")
  Label(screen8, text = "Medeelel buruu baina").pack()
  Button(screen8, text = "OK", command =delete6).pack()

def user1_not_found():
  global screen9
  screen9 = Toplevel(screen)
  screen9.title("Amjilttai")
  screen9.geometry("150x100")
  Label(screen9, text = "Medeelel oldsongui").pack()
  Button(screen9, text = "OK", command =delete7).pack()
  
def register():
  global screen1
  screen1 = Toplevel(screen)
  screen1.title("Burtgel")
  screen1.geometry("250x250")
  
  global username
  global password
  global username_entry
  global password_entry
  username = StringVar()
  password = StringVar()

  Label(screen1, text = "Doorh medeelliig shalgana uu").pack()
  Label(screen1, text = "").pack()
  Label(screen1, text = "Username * ").pack()
 
  username_entry = Entry(screen1, textvariable = username)
  username_entry.pack()
  Label(screen1, text = "Password * ").pack()
  password_entry =  Entry(screen1, textvariable = password)
  password_entry.pack()
  Label(screen1, text = "").pack()
  Button(screen1, text = "Burtguuleh", width = 10, height = 1, command = register_user).pack()

def login():
  global screen2
  screen2 = Toplevel(screen)
  screen2.title("Nevtreh")
  screen2.geometry("300x250")
  Label(screen2, text = "Door medeellee oruulan nevterne uu").pack()
  Label(screen2, text = "").pack()

  global username_verify
  global password_verify
  
  username_verify = StringVar()
  password_verify = StringVar()
  global username_entry1
  global password_entry1
  
  Label(screen2, text = "Username * ",).pack()
  username_entry1 = Entry(screen2, textvariable = username_verify)
  username_entry1.pack()
  Label(screen2, text = "").pack()
  Label(screen2, text = "Password * ",).pack()
  password_entry1 = Entry(screen2, textvariable = password_verify)
  password_entry1.pack()
  Label(screen2, text = "").pack()
  Button(screen2, text = "Nevtreh", width = 10, height = 1, command = login_verify).pack()
def serving():
  global screen14
  screen14 = Toplevel(screen)
  screen14.title("Service")
  screen14.geometry("800x550")
  img = PhotoImage(file="wave.png")
  Label(screen14, image=img, bg="black", ).place(x=0, y=0)
  Label(screen14, text="Ymr uilchilgee avahaa songono uu").pack()
  Button(screen14,text = "Cryptograph", bg = "grey", height = "4", width = "50",command = cryptograph).pack()
  Button(screen14,text = "Nmap scanner", bg = "grey", height = "4", width = "50", command = nmapping).pack()
  Button(screen14,text="GEO IP", bg="grey", height="4", width="50", command=geo_ip1).pack()
def main_screen():
  global screen
  screen = Tk()
  screen.title("Login")
  screen.geometry("2000x1200+300+200")
  screen.configure(bg="#fff")
  img = PhotoImage(file="wave.png")
  Label(screen,image=img,bg="white",).place(x=0,y=0)
  Button(text = "Nevtreh", bg = "white", height = "2", width = "30",command = login).pack()
  Button(text = "Burtguuleh", bg = "white", height = "2", width = "30", command = register).pack()

  
  screen.mainloop()

main_screen()




